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

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, Marshal and the rank tables) lives in raijin-core, shared by every
// Raijin tool. Finding, Group and Policy are specific to raijin-cors.
type (
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

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
	p.Count = core.OmitCount(p.Count, len(p.Locations))
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
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}
