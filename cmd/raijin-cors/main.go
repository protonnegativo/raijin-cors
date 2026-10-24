// Command raijin-cors tests URLs for CORS misconfigurations and returns a small, grouped, ranked result
// for AI agents: the exploitable policies first, each with a ready proof request.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/protonnegativo/raijin-cors/internal/banner"
	"github.com/protonnegativo/raijin-cors/internal/cors"
	"github.com/protonnegativo/raijin-cors/internal/reduce"
	"github.com/protonnegativo/raijin-cors/internal/schema"
	"github.com/protonnegativo/raijin-cors/internal/scope"
	"github.com/protonnegativo/raijin-cors/internal/state"
)

const version = "0.1.0"

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-cors", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var targets, headers multi
	fs.Var(&targets, "u", "target URL (repeatable); without a scheme it is tested as https://")
	fs.Var(&headers, "H", `extra request header "Name: value" (repeatable), e.g. a session cookie`)
	list := fs.String("l", "", "file with one target URL per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	rate := fs.Int("rate", 10, "requests per second")
	timeout := fs.Int("timeout", 10, "request timeout in seconds")
	threads := fs.Int("threads", 5, "concurrent requests")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for the full per-request JSONL log (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	input := fs.String("input", "", "read an existing raijin-cors raw JSONL file instead of sending requests")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-cors --scope scope.txt (-u url | -l urls.txt | --input raw.jsonl) [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-cors", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-cors", version)
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "raijin-cors: unexpected arguments (the engine is built in, so nothing goes after --):", strings.Join(fs.Args(), " "))
		return 1
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-cors: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-cors: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-cors",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}

	var obs []cors.Observation
	if *input != "" {
		f, err := os.Open(*input)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-cors:", err)
			return 1
		}
		obs, err = cors.Parse(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, "raijin-cors:", err)
			return 1
		}
		res.Target = *input
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-cors:", err)
				return 1
			}
			targets = append(targets, lines...)
		}
		inScope := filter(targets, sc, res.Omitted)
		if len(inScope) == 0 {
			fmt.Fprintln(stderr, "raijin-cors: no targets in scope")
			return 1
		}
		if _, err := cors.ParseHeaders(headers); err != nil {
			fmt.Fprintln(stderr, "raijin-cors:", err)
			return 1
		}
		var probes []cors.Probe
		for _, t := range inScope {
			p, err := cors.Origins(t)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-cors:", err)
				return 1
			}
			probes = append(probes, p...)
		}
		res.Target = targetSummary(inScope, res.Omitted["out_of_scope"])

		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-cors-*.jsonl")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-cors:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		obs, err = cors.Run(ctx, probes, cors.Options{Rate: *rate, Timeout: *timeout, Threads: *threads, Headers: headers, RawPath: *rawPath})
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "engine_error", Hint: err.Error() + fmt.Sprintf(" (%d of %d requests sent; rerun to finish)", len(obs), len(probes))})
		}
	}

	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.InScope = sc.Allowed
	findings, groups, omitted, allLocations := reduce.Reduce(obs, opt)
	res.Findings, res.Groups = findings, groups
	for k, v := range omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, allLocations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, len(obs)-omitted["out_of_scope"]-omitted["duplicates"], newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + *input; src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return 0
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// filter keeps the in-scope targets, once each. A target without a scheme becomes https://.
func filter(targets []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t != "" && !strings.Contains(t, "://") {
			t = "https://" + t
		}
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		if !sc.Allowed(t) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, t)
	}
	return out
}

func targetSummary(targets []string, skipped int) string {
	s := fmt.Sprintf("%d URL(s)", len(targets))
	if len(targets) == 1 {
		s = targets[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, requests, newCount int) string {
	urls, failed := 0, 0
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
		urls += len(f.Locations)
	}
	for _, g := range res.Groups {
		urls += len(g.Locations)
		if strings.HasPrefix(g.ID, "failed-") {
			failed += len(g.Locations)
		}
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d URLs, %d requests, %d findings", urls, requests, len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if failed > 0 {
		s += fmt.Sprintf(", %d no response", failed)
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s %s (%d)%s\n", strings.ToUpper(f.Severity), strings.Join(f.Tags, ","), f.Title, max(f.Count, len(f.Locations)), mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
			fmt.Fprintf(w, "         proof: %s\n", f.Proof)
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s (%d)\n", g.Title, max(g.Count, len(g.Locations)))
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
