package cors

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOrigins(t *testing.T) {
	p, err := Origins("https://api.target.com:8443/me")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	var order []string
	for _, x := range p {
		got[x.Test] = x.Origin
		order = append(order, x.Test)
	}
	want := map[string]string{
		"reflect":    "https://attacker.example",
		"null":       "null",
		"prefix":     "https://api.target.com.attacker.example",
		"suffix":     "https://attackerapi.target.com",
		"dot":        "https://apixtarget.com",
		"subdomain":  "https://raijin.api.target.com",
		"http":       "http://api.target.com:8443",
		"backtick":   "https://api.target.com`.attacker.example",
		"underscore": "https://api.target.com_.attacker.example",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q, want %q", k, got[k], v)
		}
	}
	if strings.Join(order, ",") != strings.Join(Tests, ",") {
		t.Errorf("probes should follow the test order: %v", order)
	}

	p, _ = Origins("http://localhost/")
	for _, x := range p {
		if x.Test == "http" || x.Test == "dot" {
			t.Errorf("http is skipped on http URLs and dot on hosts without a dot: %+v", x)
		}
	}
	if _, err := Origins("ftp://a"); err == nil {
		t.Error("only http(s) URLs")
	}
}

func TestErrorTextIsHostFree(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}
	if s := ErrorText(err); s != "connection refused" {
		t.Errorf("ErrorText = %q", s)
	}
}

// Run against a server on a lab port: one request per probe, the Origin header sent, the CORS headers
// read back, the raw JSONL written and readable by Parse.
func TestRunAndParse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:19398")
	if err != nil {
		t.Skip("lab port 19398 is busy:", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "s=1" {
			w.WriteHeader(401)
			return
		}
		if o := r.Header.Get("Origin"); o == "null" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		}
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	probes, _ := Origins(srv.URL + "/me")
	raw := filepath.Join(t.TempDir(), "raw.jsonl")
	obs, err := Run(context.Background(), probes, Options{Rate: 100, Headers: []string{"Cookie: s=1"}, RawPath: raw})
	if err != nil {
		t.Fatal(err)
	}
	if len(obs) != len(probes) {
		t.Fatalf("%d observations for %d probes", len(obs), len(probes))
	}
	for _, o := range obs {
		if o.Status != 200 {
			t.Errorf("%s: status %d (headers not sent?)", o.Test, o.Status)
		}
		if (o.Test == "null") != (o.ACAO == "null" && o.ACAC == "true" && o.Vary == "Origin") {
			t.Errorf("%s: %+v", o.Test, o)
		}
	}
	f, _ := os.Open(raw)
	defer f.Close()
	back, err := Parse(f)
	if err != nil || len(back) != len(obs) || back[1].ACAO != "null" {
		t.Errorf("raw replay: %v %+v", err, back)
	}
}

func TestParseHeaders(t *testing.T) {
	if _, err := ParseHeaders([]string{"no colon"}); err == nil {
		t.Error(`a header must be "Name: value"`)
	}
	h, err := ParseHeaders([]string{"Cookie: a=b; c=d"})
	if err != nil || h.Get("Cookie") != "a=b; c=d" {
		t.Errorf("%v %v", h, err)
	}
}
