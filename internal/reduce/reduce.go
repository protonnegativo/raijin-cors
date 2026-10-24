// Package reduce turns raw CORS observations into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every (URL, origin test, Access-Control-Allow-Origin,
// Access-Control-Allow-Credentials) observation is kept, in the policy of the entry that lists the URL.
// URLs whose every test got the same answer collapse into one entry that lists every URL. Only exact
// duplicates are dropped. A byte budget can cut, but every cut is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-cors/internal/cors"
	"github.com/protonnegativo/raijin-cors/internal/schema"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems    int // 0 keeps every finding
	MaxBytes    int
	MaxLocation int // longest location string
	InScope     func(target string) bool
}

// Defaults keep every finding and cap the JSON at a size that fits comfortably in an agent's context.
func Defaults() Options {
	return Options{MaxBytes: 16000, MaxLocation: 300}
}

// The rules that make a policy a finding, in ranking order. Each tag has a fixed severity; a finding
// takes the highest. no-vary only adds to another tag.
var tagOrder = []string{"credentials", "subdomain", "downgrade", "readable", "wildcard", "no-vary"}

var tagSeverity = map[string]string{
	"credentials": "high",
	"subdomain":   "medium",
	"downgrade":   "medium",
	"readable":    "low",
	"wildcard":    "info",
	"no-vary":     "",
}

var testRank = map[string]int{}

func init() {
	for i, t := range cors.Tests {
		testRank[t] = i
	}
}

// Outcome is what one request got, without its status: "none", "reflected" (the Origin sent came
// back), "*" or the literal Access-Control-Allow-Origin, then "+creds" when
// Access-Control-Allow-Credentials is "true" (any other value is written as "+acac=<value>"). A
// request that got no answer is "error: <reason>".
func Outcome(o cors.Observation) string {
	if o.Error != "" {
		return "error: " + o.Error
	}
	acao, acac := strings.TrimSpace(o.ACAO), strings.TrimSpace(o.ACAC)
	s := acao
	switch {
	case acao == "":
		s = "none"
	case acao == o.Origin:
		s = "reflected"
	}
	switch {
	case acac == "true":
		s += "+creds"
	case acac != "":
		s += "+acac=" + acac
	}
	return s
}

type result struct {
	test    string
	outcome string
	status  int
	noVary  bool // reflected without Origin in Vary
}

type cluster struct {
	key     string
	results []result // of the first URL; every URL in the cluster has the same
	urls    []string
	origins map[string]map[string]string // url -> test -> origin sent, for the proof
}

// Reduce collapses observations into findings and groups: one entry per distinct policy, listing every
// URL that has it. It also returns every location per finding fingerprint, before any budget, for --state.
func Reduce(obs []cors.Observation, opt Options) ([]schema.Finding, []schema.Group, map[string]int, map[string][]string) {
	omitted := map[string]int{}
	type key struct {
		url, test, origin, outcome string
		status                     int
		vary                       string
	}
	seen := map[key]bool{}
	byURL := map[string][]result{}
	origins := map[string]map[string]string{}
	var urls []string
	for _, o := range obs {
		if opt.InScope != nil && !opt.InScope(o.URL) {
			omitted["out_of_scope"]++
			continue
		}
		k := key{o.URL, o.Test, o.Origin, Outcome(o), o.Status, o.Vary}
		if seen[k] {
			omitted["duplicates"]++
			continue
		}
		seen[k] = true
		if _, ok := byURL[o.URL]; !ok {
			urls = append(urls, o.URL)
			origins[o.URL] = map[string]string{}
		}
		r := result{test: o.Test, outcome: k.outcome, status: o.Status}
		r.noVary = strings.HasPrefix(r.outcome, "reflected") && !varyOrigin(o.Vary)
		byURL[o.URL] = append(byURL[o.URL], r)
		if _, ok := origins[o.URL][o.Test]; !ok {
			origins[o.URL][o.Test] = o.Origin
		}
	}

	clusters := map[string]*cluster{}
	var keys []string
	for _, u := range urls {
		rs := byURL[u]
		sort.SliceStable(rs, func(i, j int) bool {
			if testRank[rs[i].test] != testRank[rs[j].test] {
				return testRank[rs[i].test] < testRank[rs[j].test]
			}
			return fmt.Sprint(rs[i]) < fmt.Sprint(rs[j])
		})
		sig := signature(rs)
		c, ok := clusters[sig]
		if !ok {
			c = &cluster{key: sig, results: rs, origins: map[string]map[string]string{}}
			clusters[sig] = c
			keys = append(keys, sig)
		}
		c.urls = append(c.urls, trim(u, opt.MaxLocation))
		c.origins[trim(u, opt.MaxLocation)] = origins[u]
	}

	findings := []schema.Finding{}
	groups := []schema.Group{}
	allLocations := map[string][]string{}
	proofRank := map[string]int{} // finding ID -> test rank of its proof, for the ranking
	for _, k := range keys {
		c := clusters[k]
		sort.Strings(c.urls)
		status, policy := Policy(c.results)
		tags, proofTest := Tags(c.results)
		hash := fingerprint(k)[:8]
		if len(tags) == 0 {
			groups = append(groups, schema.Group{ID: groupKind(policy, c.results) + "-" + hash, Title: groupTitle(policy, c.results), Status: status, Policy: policy, Locations: c.urls, Count: len(c.urls)})
			continue
		}
		f := schema.Finding{ID: tags[0] + "-" + hash, Title: title(tags[0], c.results), Tags: tags, Status: status, Policy: policy, Locations: c.urls, Count: len(c.urls)}
		f.Fingerprint = fingerprint(f.ID)
		for _, t := range tags {
			if schema.SeverityRank[tagSeverity[t]] > schema.SeverityRank[f.Severity] {
				f.Severity = tagSeverity[t]
			}
		}
		if tags[0] == "credentials" {
			f.Confidence = "verified"
		}
		f.Proof = Proof(c.urls[0], c.origins[c.urls[0]][proofTest])
		proofRank[f.ID] = testRank[proofTest]
		allLocations[f.Fingerprint] = c.urls
		findings = append(findings, f)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if proofRank[a.ID] != proofRank[b.ID] {
			return proofRank[a.ID] < proofRank[b.ID] // any origin before null before a prefix bypass...
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].ID < groups[j].ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	return findings, groups, omitted, allLocations
}

// Policy maps each outcome to its tests, in test order. When every answered request got the same HTTP
// status it is returned on its own; otherwise each outcome ends in " (<status>)". "none" with no status
// suffix is the default and is left out.
func Policy(rs []result) (int, schema.Policy) {
	statuses := map[int]bool{}
	for _, r := range rs {
		if r.status != 0 {
			statuses[r.status] = true
		}
	}
	status := 0
	if len(statuses) == 1 {
		for s := range statuses {
			status = s
		}
	}
	p := schema.Policy{}
	for _, r := range rs {
		k := r.outcome
		if status == 0 && r.status != 0 {
			k += fmt.Sprintf(" (%d)", r.status)
		}
		if k == "none" {
			continue
		}
		if !contains(p[k], r.test) {
			p[k] = append(p[k], r.test)
		}
	}
	if len(p) == 0 {
		p = nil
	}
	return status, p
}

// Tags returns the rules a policy matches, in a fixed order, and the test the proof uses: the first
// test (in test order) behind the highest tag. No tags means it goes to a group.
//
//	credentials  an attacker origin (reflect, null, prefix, suffix, dot, backtick, underscore) is allowed
//	             with credentials, or the server answers a literal "null" with credentials
//	subdomain    https://raijin.<host> is allowed with credentials
//	downgrade    http://<host> is allowed with credentials on an https URL
//	readable     an attacker origin is allowed without credentials
//	wildcard     Access-Control-Allow-Origin: * (browsers never send credentials with it)
//	no-vary      an origin is echoed without "Origin" in Vary, so a shared cache can serve it to others
func Tags(rs []result) ([]string, string) {
	hit := map[string]string{} // tag -> first test
	for _, r := range rs {
		base, creds := strings.CutSuffix(r.outcome, "+creds")
		var tag string
		switch {
		case base == "reflected" && creds && cors.AttackerTests[r.test]:
			tag = "credentials"
		case base == "null" && creds:
			tag = "credentials"
		case base == "reflected" && creds && r.test == "subdomain":
			tag = "subdomain"
		case base == "reflected" && creds && r.test == "http":
			tag = "downgrade"
		case strings.HasPrefix(base, "reflected") && cors.AttackerTests[r.test]:
			tag = "readable"
		case base == "*" || strings.HasPrefix(base, "*+acac="):
			tag = "wildcard"
		}
		if _, ok := hit[tag]; tag != "" && !ok {
			hit[tag] = r.test
		}
		if r.noVary {
			if _, ok := hit["no-vary"]; !ok {
				hit["no-vary"] = r.test
			}
		}
	}
	var tags []string
	for _, t := range tagOrder {
		if _, ok := hit[t]; ok {
			tags = append(tags, t)
		}
	}
	if len(tags) == 0 || tags[0] == "no-vary" {
		return nil, ""
	}
	return tags, hit[tags[0]]
}

// Proof is a curl command that sends the origin and shows the CORS headers that came back.
func Proof(url, origin string) string {
	return "curl -si -H " + quote("Origin: "+origin) + " " + quote(url)
}

func title(tag string, rs []result) string {
	var tests []string
	for _, r := range rs {
		base, creds := strings.CutSuffix(r.outcome, "+creds")
		switch tag {
		case "credentials":
			if creds && (base == "null" || base == "reflected" && cors.AttackerTests[r.test]) {
				tests = append(tests, r.test)
			}
		case "readable":
			if strings.HasPrefix(base, "reflected") && cors.AttackerTests[r.test] {
				tests = append(tests, r.test)
			}
		case "wildcard":
			if creds && base == "*" {
				return "Wildcard origin with credentials (browsers refuse to send them)"
			}
		}
	}
	switch tag {
	case "credentials":
		switch {
		case contains(tests, "reflect"):
			return "Any origin reflected with credentials"
		case len(tests) == 1 && tests[0] == "null":
			return "null origin allowed with credentials"
		}
		return "Origin check bypassed with credentials (" + strings.Join(tests, ", ") + ")"
	case "subdomain":
		return "Any subdomain allowed with credentials"
	case "downgrade":
		return "http:// origin allowed with credentials on https"
	case "readable":
		if contains(tests, "reflect") {
			return "Any origin reflected without credentials"
		}
		return "Origin check bypassed without credentials (" + strings.Join(tests, ", ") + ")"
	}
	return "Wildcard origin"
}

func groupKind(p schema.Policy, rs []result) string {
	switch {
	case allErrors(rs):
		return "failed"
	case anyError(rs):
		return "partial"
	case len(p) == 0:
		return "none"
	}
	return "allowlist"
}

func groupTitle(p schema.Policy, rs []result) string {
	switch {
	case allErrors(rs):
		return "No response"
	case anyError(rs):
		return "Some requests got no response"
	case len(p) == 0:
		return "No CORS headers"
	}
	return "Attacker origins not allowed"
}

func allErrors(rs []result) bool {
	for _, r := range rs {
		if !strings.HasPrefix(r.outcome, "error: ") {
			return false
		}
	}
	return len(rs) > 0
}

func anyError(rs []result) bool {
	for _, r := range rs {
		if strings.HasPrefix(r.outcome, "error: ") {
			return true
		}
	}
	return false
}

// signature is what makes two URLs share an entry: every test with its outcome, status and Vary.
func signature(rs []result) string {
	parts := make([]string, len(rs))
	for i, r := range rs {
		parts[i] = fmt.Sprintf("%s=%s|%d|%v", r.test, r.outcome, r.status, r.noVary)
	}
	return strings.Join(parts, "\n")
}

func varyOrigin(v string) bool {
	for _, f := range strings.Split(v, ",") {
		if f = strings.TrimSpace(f); f == "*" || strings.EqualFold(f, "origin") {
			return true
		}
	}
	return false
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

// quote wraps s in single quotes for a POSIX shell.
func quote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

func trim(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
