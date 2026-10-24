package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-cors",
		Findings: []Finding{{ID: "credentials-ab12cd34", Title: "t", Severity: "high", Tags: []string{"credentials"}, Policy: Policy{"reflected+creds": {"reflect"}}, Locations: []string{"https://a", "https://b"}, Count: 2, Proof: "curl", Fingerprint: "fp"}},
		Groups:   []Group{{ID: "none-ef56ab78", Title: "No CORS headers", Locations: []string{"https://c"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "status", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Count(string(b), `"policy"`) != 1 {
		t.Errorf("a group with no policy (every test got none) leaves it out: %s", b)
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestFindingShape(t *testing.T) {
	f := Finding{ID: "credentials-x", Title: "Any origin reflected with credentials", Severity: "high", Confidence: "verified", Tags: []string{"credentials"}, Status: 200, Policy: Policy{"reflected+creds": {"reflect", "null"}}, Locations: []string{"https://a"}, Proof: "curl -si -H 'Origin: https://attacker.example' 'https://a'"}
	b, _ := json.Marshal(f)
	want := `{"id":"credentials-x","title":"Any origin reflected with credentials","severity":"high","confidence":"verified","tags":["credentials"],"status":200,"policy":{"reflected+creds":["reflect","null"]},"locations":["https://a"],"proof":"curl -si -H 'Origin: https://attacker.example' 'https://a'"}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "credentials-x", Tags: []string{"credentials"}, Locations: []string{"https://a"}, Count: 7}},
		Groups:   []Group{{ID: "none-y", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["https://a"],"count":7`) || !strings.Contains(s, `{"id":"none-y","title":"","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
