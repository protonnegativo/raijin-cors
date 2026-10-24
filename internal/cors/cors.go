// Package cors is the native engine: it sends one GET per origin test to each URL and logs what the
// server answered in the CORS headers.
//
// Every request is one Observation, one line of the raw JSONL. That file is the engine output the
// reducer reads, and the one --input replays.
package cors

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Attacker is the host of the attacker-controlled origins. .example is reserved (RFC 2606), so no
// request ever goes there: it is only written in the Origin header.
const Attacker = "attacker.example"

// Tests are the origin tests, in the order they run and are ranked. Each builds the Origin header from
// the URL's host (without its port, unless said):
//
//	reflect     https://attacker.example                any origin is echoed
//	null        null                                    sandboxed iframes, data: and file: pages send it
//	prefix      https://<host>.attacker.example         the check only looks at the start ("starts with target.com")
//	suffix      https://attacker<host>                  the check only looks at the end ("ends with target.com")
//	dot         https://<host, first "." -> "x">        an unescaped "." in a regex (api.target.com -> apixtarget.com)
//	subdomain   https://raijin.<host>                   every subdomain is trusted (exploitable with XSS or a takeover there)
//	http        http://<host[:port]>                    an https URL trusts its http origin (exploitable by a network attacker); https URLs only
//	backtick    https://<host>`.attacker.example        a parser that stops at "`" (Safari sends this origin)
//	underscore  https://<host>_.attacker.example        a parser that stops at "_" (Chrome and Firefox send this origin)
//
// dot is skipped when the host has no ".", and http is skipped on http URLs (it is their own origin).
var Tests = []string{"reflect", "null", "prefix", "suffix", "dot", "subdomain", "http", "backtick", "underscore"}

// AttackerTests are the tests whose origin an attacker can host or forge without touching the target.
var AttackerTests = map[string]bool{"reflect": true, "null": true, "prefix": true, "suffix": true, "dot": true, "backtick": true, "underscore": true}

// Probe is one request to send: a URL, a test and the Origin it sends.
type Probe struct {
	URL    string
	Test   string
	Origin string
}

// Origins returns the probes for one URL, in test order.
func Origins(rawURL string) ([]Probe, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("not an http(s) URL: %q", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]" // IPv6
	}
	var out []Probe
	for _, t := range Tests {
		o := ""
		switch t {
		case "reflect":
			o = "https://" + Attacker
		case "null":
			o = "null"
		case "prefix":
			o = "https://" + host + "." + Attacker
		case "suffix":
			o = "https://attacker" + host
		case "dot":
			if strings.Contains(host, ".") {
				o = "https://" + strings.Replace(host, ".", "x", 1)
			}
		case "subdomain":
			o = "https://raijin." + host
		case "http":
			if u.Scheme == "https" {
				o = "http://" + strings.ToLower(u.Host)
			}
		case "backtick":
			o = "https://" + host + "`." + Attacker
		case "underscore":
			o = "https://" + host + "_." + Attacker
		}
		if o != "" {
			out = append(out, Probe{URL: rawURL, Test: t, Origin: o})
		}
	}
	return out, nil
}

// Observation is one request and the CORS headers of its answer: one line of the raw JSONL.
type Observation struct {
	Time   string `json:"time,omitempty"`
	URL    string `json:"url"`
	Test   string `json:"test"`
	Origin string `json:"origin"`
	Method string `json:"method,omitempty"`
	Status int    `json:"status"`
	// ACAO and ACAC are Access-Control-Allow-Origin and Access-Control-Allow-Credentials, as sent
	// (several headers joined with ", ").
	ACAO string `json:"acao"`
	ACAC string `json:"acac"`
	Vary string `json:"vary"`
	// ACAM, ACAH and ACEH are Access-Control-Allow-Methods, -Allow-Headers and -Expose-Headers.
	ACAM  string `json:"acam,omitempty"`
	ACAH  string `json:"acah,omitempty"`
	ACEH  string `json:"aceh,omitempty"`
	MS    int64  `json:"ms,omitempty"`
	Error string `json:"error,omitempty"`
}

// Options control the requests.
type Options struct {
	Rate    int // requests per second across all workers; 0 means 10
	Timeout int // seconds per request; 0 means 10
	Threads int // concurrent requests; 0 means 5
	Headers []string
	RawPath string
}

// Run sends every probe and returns one observation per probe, in probe order. It writes them to
// RawPath as JSONL. On ctx cancel it returns what it has.
func Run(ctx context.Context, probes []Probe, opt Options) ([]Observation, error) {
	if opt.Rate <= 0 {
		opt.Rate = 10
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 10
	}
	if opt.Threads <= 0 {
		opt.Threads = 5
	}
	headers, err := ParseHeaders(opt.Headers)
	if err != nil {
		return nil, err
	}
	client := &http.Client{
		Timeout: time.Duration(opt.Timeout) * time.Second,
		// The CORS headers that matter are on the response itself, so redirects are not followed.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, // a test target's certificate is often self-signed
			MaxIdleConnsPerHost: opt.Threads,
		},
	}

	out := make([]Observation, len(probes))
	done := make([]bool, len(probes))
	tick := time.NewTicker(time.Second / time.Duration(opt.Rate))
	defer tick.Stop()
	jobs := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < opt.Threads; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				out[i] = send(ctx, client, probes[i], headers)
				done[i] = true
			}
		}()
	}
feed:
	for i := range probes {
		select {
		case <-ctx.Done():
			break feed
		case <-tick.C:
		}
		select {
		case <-ctx.Done():
			break feed
		case jobs <- i:
		}
	}
	close(jobs)
	wg.Wait()

	var obs []Observation
	for i, ok := range done {
		if ok {
			obs = append(obs, out[i])
		}
	}
	if opt.RawPath != "" {
		if err := writeJSONL(opt.RawPath, obs); err != nil {
			return obs, err
		}
	}
	return obs, ctx.Err()
}

// ParseHeaders reads "Name: value" lines into a header set.
func ParseHeaders(lines []string) (http.Header, error) {
	h := http.Header{}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, ":")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("header %q is not \"Name: value\"", l)
		}
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	return h, nil
}

func send(ctx context.Context, client *http.Client, p Probe, headers http.Header) Observation {
	o := Observation{Time: time.Now().Format(time.RFC3339Nano), URL: p.URL, Test: p.Test, Origin: p.Origin, Method: http.MethodGet}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
	if err != nil {
		o.Error = err.Error()
		return o
	}
	for k, v := range headers {
		req.Header[k] = v
	}
	req.Header.Set("Origin", p.Origin)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "raijin-cors")
	}
	start := time.Now()
	resp, err := client.Do(req)
	o.MS = time.Since(start).Milliseconds()
	if err != nil {
		o.Error = ErrorText(err)
		return o
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	o.Status = resp.StatusCode
	h := resp.Header
	o.ACAO = strings.Join(h.Values("Access-Control-Allow-Origin"), ", ")
	o.ACAC = strings.Join(h.Values("Access-Control-Allow-Credentials"), ", ")
	o.Vary = strings.Join(h.Values("Vary"), ", ")
	o.ACAM = strings.Join(h.Values("Access-Control-Allow-Methods"), ", ")
	o.ACAH = strings.Join(h.Values("Access-Control-Allow-Headers"), ", ")
	o.ACEH = strings.Join(h.Values("Access-Control-Expose-Headers"), ", ")
	return o
}

// ErrorText is a short, host-free reason a request failed, so URLs that failed the same way collapse:
// "connection refused", "timeout", "no such host", or Go's error without the request URL.
func ErrorText(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := err.Error()
	if strings.Contains(s, "dial tcp") {
		if i := strings.LastIndex(s, ": "); i >= 0 {
			s = s[i+2:]
		}
	}
	return s
}

func writeJSONL(path string, obs []Observation) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for _, o := range obs {
		if err := enc.Encode(o); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Parse reads raw JSONL. Lines that are not JSON objects are skipped.
func Parse(r io.Reader) ([]Observation, error) {
	var out []Observation
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var o Observation
		if err := json.Unmarshal([]byte(line), &o); err != nil {
			return nil, fmt.Errorf("raw line: %w", err)
		}
		if o.URL == "" {
			continue
		}
		out = append(out, o)
	}
	return out, sc.Err()
}
