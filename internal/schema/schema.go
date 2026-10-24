// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engine found is dropped silently: every tested URL is listed, in a finding or in a group,
// and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the locations listed, and
// fields at their documented default.
//
// raijin-cors adds the CORS policy (which origin tests got which Access-Control-Allow-Origin and
// Access-Control-Allow-Credentials answer), the HTTP status and, on findings, a ready proof request.
package schema

import (
	"bytes"
	"encoding/json"
)

// Marshal is json.Marshal without HTML escaping: "<" and "&" stay readable instead of "<", which
// costs tokens and nothing else.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// Result is the top-level object a Raijin tool writes to stdout.
type Result struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Findings []Finding      `json:"findings"`
	Groups   []Group        `json:"groups"`
	Omitted  map[string]int `json:"omitted,omitempty"`
	Errors   []Error        `json:"errors,omitempty"`
	Next     []string       `json:"next,omitempty"`
	// Raw is the file with the engine's full output, for details the result leaves out.
	Raw    string `json:"raw,omitempty"`
	Budget Budget `json:"budget"`
}

// MarshalJSON writes the budget only when something was cut.
func (r Result) MarshalJSON() ([]byte, error) {
	type plain Result
	out := struct {
		plain
		Budget *Budget `json:"budget,omitempty"`
	}{plain: plain(r)}
	if r.Budget.Truncated {
		out.Budget = &r.Budget
	}
	return Marshal(out)
}

// Policy maps an outcome to the origin tests that got it, for example
// {"reflected+creds": ["reflect", "null"], "*": ["subdomain"]}. A test that is not listed got no
// Access-Control-Allow-Origin and no Access-Control-Allow-Credentials ("none", the documented default).
type Policy map[string][]string

// Finding is one exploitable or notable CORS policy with every URL that has it. The same tool and ID in
// two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules that made it a finding: credentials, subdomain, downgrade, readable, wildcard, no-vary.
	Tags []string `json:"tags"`
	// Status is the HTTP status every request got; it is left out when they differ (each outcome then
	// says its status) or when no request was answered.
	Status int    `json:"status,omitempty"`
	Policy Policy `json:"policy"`
	// Locations are every URL with this policy.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Proof is a curl command that shows the misconfiguration on the first location.
	Proof string `json:"proof"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Group is one policy no rule flagged (no CORS headers, a fixed allowlist, a trusted subdomain without
// credentials, no response), with every URL that has it. 40 URLs with no CORS headers are one group.
type Group struct {
	ID        string   `json:"id"`
	Title     string   `json:"title"`
	Status    int      `json:"status,omitempty"`
	Policy    Policy   `json:"policy,omitempty"`
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	if p.Count <= len(p.Locations) {
		p.Count = 0
	}
	return Marshal(p)
}

// Error is a problem during the run, with a hint about what to try next.
type Error struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// Budget reports the output limits that were applied.
type Budget struct {
	MaxItems  int  `json:"max_items"`
	MaxBytes  int  `json:"max_bytes"`
	Truncated bool `json:"truncated"`
}

// SeverityRank orders severities from most to least important.
var SeverityRank = map[string]int{
	"critical": 5,
	"high":     4,
	"medium":   3,
	"low":      2,
	"info":     1,
	"unknown":  0,
}

// ConfidenceRank orders confidence values: a verified finding before a matched one before a heuristic one.
var ConfidenceRank = map[string]int{
	"verified":  2,
	"":          1,
	"heuristic": 0,
}
