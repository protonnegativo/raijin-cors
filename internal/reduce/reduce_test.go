package reduce

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-cors/internal/cors"
	"github.com/protonnegativo/raijin-cors/internal/schema"
)

func load(t *testing.T) []cors.Observation {
	t.Helper()
	f, err := os.Open("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	obs, err := cors.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	return obs
}

// observe runs every origin test on url and answers with fn(test, origin) -> acao, acac.
func observe(url string, fn func(test, origin string) (string, string)) []cors.Observation {
	probes, err := cors.Origins(url)
	if err != nil {
		panic(err)
	}
	var out []cors.Observation
	for _, p := range probes {
		acao, acac := fn(p.Test, p.Origin)
		out = append(out, cors.Observation{URL: url, Test: p.Test, Origin: p.Origin, Status: 200, ACAO: acao, ACAC: acac, Vary: "Origin"})
	}
	return out
}

func reflectCreds(_, origin string) (string, string) { return origin, "true" }
func noCORS(_, _ string) (string, string)            { return "", "" }

func TestReduce(t *testing.T) {
	obs := load(t)
	if len(obs) != 64 {
		t.Fatalf("parsed %d observations, want 64 (the log line is skipped)", len(obs))
	}
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed

	findings, groups, omitted, all := Reduce(obs, opt)

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	high, wild := findings[0], findings[1]
	if high.Severity != "high" || high.Confidence != "verified" || high.Title != "Any origin reflected with credentials" || strings.Join(high.Tags, ",") != "credentials,subdomain,downgrade" {
		t.Errorf("first finding = %+v", high)
	}
	if strings.Join(high.Locations, ",") != "https://api.example.com/me,https://api.example.com/orders" {
		t.Errorf("URLs with the same policy share one finding: %v", high.Locations)
	}
	if len(high.Policy["reflected+creds"]) != 9 || high.Status != 200 {
		t.Errorf("policy = %v, status %d", high.Policy, high.Status)
	}
	if high.Proof != "curl -si -H 'Origin: https://attacker.example' 'https://api.example.com/me'" {
		t.Errorf("proof = %s", high.Proof)
	}
	if wild.Severity != "info" || strings.Join(wild.Tags, ",") != "wildcard" {
		t.Errorf("wildcard finding = %+v", wild)
	}
	if len(groups) != 3 {
		t.Fatalf("got %d groups, want 3: %+v", len(groups), groups)
	}
	byKind := map[string]schema.Group{}
	for _, g := range groups {
		byKind[strings.SplitN(g.ID, "-", 2)[0]] = g
	}
	if g := byKind["none"]; g.Title != "No CORS headers" || g.Policy != nil || g.Locations[0] != "https://www.example.com/" {
		t.Errorf("no CORS headers is a group with no policy: %+v", g)
	}
	if g := byKind["allowlist"]; len(g.Policy["https://shop.example.com+creds"]) != 9 {
		t.Errorf("a fixed origin is a group that keeps the literal value: %+v", g)
	}
	if g := byKind["failed"]; g.Status != 0 || len(g.Policy["error: connection refused"]) != 9 {
		t.Errorf("a dead URL is a group with its error: %+v", g)
	}
	if omitted["duplicates"] != 1 || omitted["out_of_scope"] != 9 {
		t.Errorf("omitted = %v", omitted)
	}
	if len(all[high.Fingerprint]) != 2 {
		t.Errorf("state locations = %v", all[high.Fingerprint])
	}
}

// Every URL is in exactly one entry: identical policies collapse, but no URL is dropped.
func TestEveryURLIsListedOnce(t *testing.T) {
	var obs []cors.Observation
	for i := 0; i < 40; i++ {
		obs = append(obs, observe(fmt.Sprintf("https://h%02d.example.com/api", i), noCORS)...)
	}
	obs = append(obs, observe("https://x.example.com/api", reflectCreds)...)
	findings, groups, omitted, _ := Reduce(obs, Defaults())
	seen := map[string]int{}
	for _, f := range findings {
		for _, l := range f.Locations {
			seen[l]++
		}
	}
	for _, g := range groups {
		for _, l := range g.Locations {
			seen[l]++
		}
	}
	if len(seen) != 41 {
		t.Errorf("listed %d URLs, want 41", len(seen))
	}
	for l, n := range seen {
		if n != 1 {
			t.Errorf("%s listed %d times", l, n)
		}
	}
	if len(groups) != 1 || len(groups[0].Locations) != 40 {
		t.Errorf("40 URLs without CORS headers should be one group: %+v", groups)
	}
	if len(omitted) != 0 {
		t.Errorf("nothing should be omitted: %v", omitted)
	}
}

// Every (test, outcome) pair is kept: a URL where tests got different answers lists each.
func TestEveryTestOutcomeIsKept(t *testing.T) {
	obs := observe("https://api.example.com/x", func(test, origin string) (string, string) {
		switch test {
		case "null":
			return "null", "true"
		case "subdomain":
			return origin, ""
		case "http":
			return "https://api.example.com", "true"
		}
		return "", ""
	})
	findings, _, _, _ := Reduce(obs, Defaults())
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	p := findings[0].Policy
	want := schema.Policy{"reflected+creds": {"null"}, "reflected": {"subdomain"}, "https://api.example.com+creds": {"http"}}
	if fmt.Sprint(p) != fmt.Sprint(want) {
		t.Errorf("policy = %v, want %v", p, want)
	}
	if f := findings[0]; f.Title != "null origin allowed with credentials" || f.Proof != "curl -si -H 'Origin: null' 'https://api.example.com/x'" {
		t.Errorf("finding = %+v", f)
	}
}

// Only exact repeats collapse; the same URL and test with a different answer is kept.
func TestSameTestDifferentAnswerIsKept(t *testing.T) {
	a := cors.Observation{URL: "https://a.example.com/", Test: "reflect", Origin: "https://attacker.example", Status: 200}
	b := a
	b.ACAO, b.ACAC = a.Origin, "true"
	findings, groups, omitted, _ := Reduce([]cors.Observation{a, b, b}, Defaults())
	if omitted["duplicates"] != 1 {
		t.Errorf("one exact repeat: %v", omitted)
	}
	if len(groups) != 0 || len(findings) != 1 {
		t.Fatalf("findings %+v groups %+v", findings, groups)
	}
	if p := findings[0].Policy; len(p) != 1 || p["reflected+creds"][0] != "reflect" {
		t.Errorf("policy = %v", p)
	}
}

// A status that differs between tests is written on each outcome instead of the entry.
func TestMixedStatusIsWrittenPerOutcome(t *testing.T) {
	obs := observe("https://a.example.com/", noCORS)
	obs[1].Status = 403
	_, groups, _, _ := Reduce(obs, Defaults())
	g := groups[0]
	if g.Status != 0 || len(g.Policy["none (200)"]) != len(obs)-1 || g.Policy["none (403)"][0] != "null" {
		t.Errorf("group = %+v", g)
	}
}

func TestRulesAndSeverity(t *testing.T) {
	cases := []struct {
		name     string
		fn       func(test, origin string) (string, string)
		severity string
		tags     string
		title    string
	}{
		{"prefix bypass", func(test, origin string) (string, string) {
			if test == "prefix" {
				return origin, "true"
			}
			return "", ""
		}, "high", "credentials", "Origin check bypassed with credentials (prefix)"},
		{"trusted subdomain", func(test, origin string) (string, string) {
			if test == "subdomain" {
				return origin, "true"
			}
			return "", ""
		}, "medium", "subdomain", "Any subdomain allowed with credentials"},
		{"downgrade", func(test, origin string) (string, string) {
			if test == "http" {
				return origin, "true"
			}
			return "", ""
		}, "medium", "downgrade", "http:// origin allowed with credentials on https"},
		{"no credentials", func(_, origin string) (string, string) { return origin, "" }, "low", "readable", "Any origin reflected without credentials"},
		{"wildcard with credentials", func(_, _ string) (string, string) { return "*", "true" }, "info", "wildcard", "Wildcard origin with credentials (browsers refuse to send them)"},
	}
	for _, c := range cases {
		findings, _, _, _ := Reduce(observe("https://a.example.com/", c.fn), Defaults())
		if len(findings) != 1 {
			t.Errorf("%s: findings = %+v", c.name, findings)
			continue
		}
		f := findings[0]
		if f.Severity != c.severity || strings.Join(f.Tags, ",") != c.tags || f.Title != c.title {
			t.Errorf("%s: got %s %v %q", c.name, f.Severity, f.Tags, f.Title)
		}
	}
	// a subdomain allowed without credentials is how most allowlists work: a group, not a finding
	findings, groups, _, _ := Reduce(observe("https://a.example.com/", func(test, origin string) (string, string) {
		if test == "subdomain" {
			return origin, ""
		}
		return "", ""
	}), Defaults())
	if len(findings) != 0 || len(groups) != 1 || groups[0].Title != "Attacker origins not allowed" {
		t.Errorf("findings %+v groups %+v", findings, groups)
	}
}

func TestNoVaryIsTagged(t *testing.T) {
	obs := observe("https://a.example.com/", reflectCreds)
	for i := range obs {
		obs[i].Vary = "Accept-Encoding"
	}
	findings, _, _, _ := Reduce(obs, Defaults())
	if tags := strings.Join(findings[0].Tags, ","); tags != "credentials,subdomain,downgrade,no-vary" {
		t.Errorf("tags = %s", tags)
	}
}

func TestRankingIsDeterministic(t *testing.T) {
	only := func(name string) func(test, origin string) (string, string) {
		return func(test, origin string) (string, string) {
			if test == name {
				return origin, "true"
			}
			return "", ""
		}
	}
	var obs []cors.Observation
	obs = append(obs, observe("https://u.example.com/", only("underscore"))...)
	obs = append(obs, observe("https://s.example.com/", only("subdomain"))...)
	obs = append(obs, observe("https://n.example.com/", only("null"))...)
	obs = append(obs, observe("https://r.example.com/", reflectCreds)...)
	findings, _, _, _ := Reduce(obs, Defaults())
	var got []string
	for _, f := range findings {
		got = append(got, f.Locations[0])
	}
	want := "https://r.example.com/,https://n.example.com/,https://u.example.com/,https://s.example.com/"
	if strings.Join(got, ",") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
}

func TestProofQuotesTheOrigin(t *testing.T) {
	if p := Proof("https://a.example.com/x?a=1&b=2", "https://a.example.com`.attacker.example"); p != "curl -si -H 'Origin: https://a.example.com`.attacker.example' 'https://a.example.com/x?a=1&b=2'" {
		t.Errorf("proof = %s", p)
	}
	if p := Proof("https://a/'x", "null"); !strings.HasSuffix(p, `'https://a/'\''x'`) {
		t.Errorf("single quotes must be escaped: %s", p)
	}
}

func TestFitCutsLeastImportantFirst(t *testing.T) {
	var obs []cors.Observation
	for i := 0; i < 200; i++ {
		obs = append(obs, observe(fmt.Sprintf("https://h%03d.example.com/api", i), noCORS)...)
	}
	obs = append(obs, observe("https://x.example.com/api", reflectCreds)...)
	findings, groups, _, _ := Reduce(obs, Defaults())
	res := schema.Result{Tool: "raijin-cors", Findings: findings, Groups: groups, Budget: schema.Budget{MaxBytes: 1500}}
	Fit(&res, 1500)
	b, _ := schema.Marshal(res)
	if len(b) > 1500 {
		t.Errorf("output is %d bytes", len(b))
	}
	if !res.Budget.Truncated || res.Omitted["locations"] != 200 || len(res.Findings) != 1 || len(res.Findings[0].Locations) != 1 {
		t.Errorf("group locations go first, the finding stays: omitted %v, findings %+v", res.Omitted, res.Findings)
	}
}

func TestOutcome(t *testing.T) {
	cases := []struct {
		o    cors.Observation
		want string
	}{
		{cors.Observation{Origin: "null"}, "none"},
		{cors.Observation{Origin: "null", ACAO: "null", ACAC: "true"}, "reflected+creds"},
		{cors.Observation{Origin: "https://e", ACAO: "*"}, "*"},
		{cors.Observation{Origin: "https://e", ACAO: "https://app", ACAC: "TRUE"}, "https://app+acac=TRUE"},
		{cors.Observation{Origin: "https://e", ACAC: "true"}, "none+creds"},
		{cors.Observation{Origin: "https://e", Error: "timeout"}, "error: timeout"},
	}
	for _, c := range cases {
		if got := Outcome(c.o); got != c.want {
			t.Errorf("Outcome(%+v) = %q, want %q", c.o, got, c.want)
		}
	}
}

// A URL where only some requests failed keeps both the errors and the answers, and says so.
func TestPartialFailureIsItsOwnGroup(t *testing.T) {
	obs := observe("https://a.example.com/", noCORS)
	obs[0].Status, obs[0].Error = 0, "connection refused"
	_, groups, _, _ := Reduce(obs, Defaults())
	g := groups[0]
	if !strings.HasPrefix(g.ID, "partial-") || g.Title != "Some requests got no response" || g.Status != 200 || g.Policy["error: connection refused"][0] != "reflect" || len(g.Policy) != 1 {
		t.Errorf("group = %+v", g)
	}
}
