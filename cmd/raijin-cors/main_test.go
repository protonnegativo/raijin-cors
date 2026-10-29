package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-cors "+version()) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
}

func TestSummaryAndProofAreReadable(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	if !strings.Contains(s, `"summary":"6 URLs, 54 requests, 2 findings (1 high, 1 info), 3 groups, 1 no response"`) {
		t.Errorf("summary: %s", s)
	}
	if !strings.Contains(s, `"proof":"curl -si -H 'Origin: https://attacker.example' 'https://api.example.com/me'"`) || strings.Contains(s, `&`) {
		t.Errorf("proof should be a ready command: %s", s)
	}
	if !strings.Contains(s, `"omitted":{"duplicates":1,"out_of_scope":9}`) {
		t.Errorf("omitted: %s", s)
	}
}

func TestBudgetCutsAreCountedAndPointToRaw(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--max-bytes", "900"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if out.Len() > 901 {
		t.Errorf("output is %d bytes with --max-bytes 900", out.Len())
	}
	var v struct {
		Omitted map[string]int
		Next    []string
		Budget  struct{ Truncated bool }
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || !v.Budget.Truncated || len(v.Next) != 1 || !strings.Contains(v.Next[0], "sample.jsonl") || v.Omitted["locations"] == 0 {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://out.of-scope.net"}, &out, &errb); code != 1 {
		t.Errorf("no target in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com", "-H", "nocolon"}, &out, &errb); code != 1 {
		t.Errorf("bad header: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-u", "https://a.example.com", "--", "-x"}, &out, &errb); code != 1 {
		t.Errorf("args after --: exit %d, want 1", code)
	}
	if out.Len() != 0 {
		t.Errorf("usage errors write nothing to stdout: %q", out.String())
	}
}

// With only --scope, every host the scope names is tested as https://<host>/ and wildcards get a
// next step. A scope names hostnames, not ports, so this checks the raw log of what was sent
// (127.0.0.1:443 needs no live server: a refused connection is still logged).
func TestScopeAloneTestsWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	if err := os.WriteFile(scopePath, []byte("127.0.0.1\n*.example.com\n!127.0.0.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := filepath.Join(dir, "raw.jsonl")
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--raw", raw, "--timeout", "2"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	urls := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var o struct{ URL string }
		if err := json.Unmarshal([]byte(l), &o); err != nil {
			t.Fatal(err)
		}
		urls[o.URL] = true
	}
	if len(urls) != 1 || !urls["https://127.0.0.1/"] {
		t.Errorf("tested URLs = %v", urls)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 1 || !strings.Contains(res.Next[0], "raijin-subs --scope "+scopePath+" -d example.com") {
		t.Errorf("next = %v", res.Next)
	}
}

// A scope of wildcards only has nothing to test: the result carries the next steps and exits 2.
func TestScopeWithNoSingleHost(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t)}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
		t.Errorf("stdout starts with %.40s", out.String())
	}
	var res struct {
		Summary string
		Next    []string
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || len(res.Next) != 1 || res.Summary != "the scope names no single host to scan" {
		t.Errorf("res = %+v err = %v", res, err)
	}
}

func TestSchemaVersionIsTheFirstField(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,"tool":"raijin-cors",`) {
		t.Errorf("output starts with %.60s", out.String())
	}
}

// An invalid scope is reported as structured errors, one per bad line, and nothing is scanned.
func TestInvalidScopeIsAStructuredError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("example.com\nexample.org:443\n10.0.0.7/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", p, "-u", "https://example.com/"}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.HasPrefix(out.String(), `{"schema_version":1,`) {
		t.Errorf("stdout starts with %.40s", out.String())
	}
	var res struct {
		SchemaVersion int `json:"schema_version"`
		Summary       string
		Findings      []any
		Errors        []struct{ Kind, Hint string }
		Raw           string
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatalf("stdout is not JSON: %v: %q", err, out.String())
	}
	if res.SchemaVersion != 1 || res.Summary != "invalid scope file, nothing scanned" || len(res.Findings) != 0 || res.Raw != "" {
		t.Errorf("res = %+v", res)
	}
	if len(res.Errors) != 2 {
		t.Fatalf("errors = %+v, want one per invalid line", res.Errors)
	}
	for i, want := range []string{"line 2: port in rule 'example.org:443'", "line 3: CIDR has host bits set '10.0.0.7/24'"} {
		if res.Errors[i].Kind != "scope" || !strings.Contains(res.Errors[i].Hint, want) {
			t.Errorf("error %d = %+v, want kind scope and %q", i, res.Errors[i], want)
		}
	}
}

func TestMissingScopeFileIsAStructuredError(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", filepath.Join(t.TempDir(), "nope.txt")}, &out, &errb); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var res struct{ Errors []struct{ Kind, Hint string } }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || len(res.Errors) != 1 || res.Errors[0].Kind != "scope" {
		t.Errorf("stdout = %q err = %v", out.String(), err)
	}
}

// --state marks findings as new once, through the core's state.Mark.
func TestStateMarksNewOnce(t *testing.T) {
	st := filepath.Join(t.TempDir(), "state.json")
	args := []string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--state", st}
	var first, second, errb bytes.Buffer
	if code := run(args, &first, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if code := run(args, &second, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(first.String(), `, 2 new"`) || !strings.Contains(first.String(), `"new":true`) {
		t.Errorf("first run should mark both findings new: %s", first.String())
	}
	if !strings.Contains(second.String(), `, 0 new"`) || strings.Contains(second.String(), `"new":true`) {
		t.Errorf("second run should mark nothing new: %s", second.String())
	}
}
