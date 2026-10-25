# ⚡ Raijin CORS

**CORS testing for AI agents: only the exploitable policies (credentials + a reflected, null or bypassed origin) as findings, each with the proof request, and every other answer grouped.**

`raijin-cors` is a tool of **Raijin**, an arsenal of offensive security tools built for AI agents. It has no external engine: it sends one GET per origin test to each URL with Go's `net/http`, logs every answer, and returns the **Raijin Schema**: one compact JSON where URLs with the same CORS policy share one entry, the policies an attacker can exploit are ranked findings with a ready `curl` proof, and anything it had to cut is counted.

## Why not just run curl?

Testing CORS by hand is a loop: for each URL, send an `Origin` header for every bypass, read `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials`, and decide whether the combination is exploitable. An agent pays for every byte of that loop. Nine origins on 46 URLs is 368 responses, and nearly all of them say "no CORS headers".

Here is the same test, with the same requests, read by an agent (tokens, `o200k_base`):

```
Noisy run: 46 URLs, 368 requests, 1 exploitable endpoint
  raijin-cors     ▉                         1,272 tokens
  curl loop       ███████████████████      28,850 tokens
  raw JSONL       ████████████████████     30,280 tokens

Findings run: 15 URLs, 121 requests, one per CORS policy
  raijin-cors     ███▏                      1,557 tokens
  curl loop       ███████████████████▌      9,659 tokens
  raw JSONL       ████████████████████      9,891 tokens
```

raijin-cors reads **24×** fewer tokens than its own per-request log on the noisy run and **6.4×** fewer on the findings run, and **23×** and **6.2×** fewer than a `curl -D -` loop that prints only the response headers. Each run's bars are drawn to scale against the raw JSONL.

- **Nothing is lost.** Every request is in the output: the URL is in exactly one entry, and that entry's `policy` says which `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` each origin test got. `bench/verify.py` checked all 489 requests in both runs and none were missing.
- **The exploitable policies come first.** An origin that is echoed with `Access-Control-Allow-Credentials: true` is a high finding with the request that proves it. 30 URLs with no CORS headers are one group that lists all 30.
- **Output is bounded.** On a huge test, `--max-bytes` cuts the least important data first and counts every cut. A curl loop grows with every request.
- **Details are one file away.** Every request is logged to a JSONL file whose path is in `raw`: the time, the origin sent, the status, `Access-Control-Allow-Origin`, `-Credentials`, `-Methods`, `-Headers`, `-Expose-Headers`, `Vary` and the latency. It costs no tokens until the agent opens it.

There is no external engine, so the baselines are the tool's own full log (the `raw` file) and the curl loop an agent would write instead. Full method and numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-cors/cmd/raijin-cors@latest
```

Nothing else is needed: the requests are sent by the binary.

## Usage

```bash
raijin-cors --scope scope.txt                                      # test every host the scope names
raijin-cors --scope scope.txt -u https://api.example.com/v1/me
raijin-cors --scope scope.txt -l urls.txt -H 'Cookie: session=...'   # send your session with every request
raijin-cors --scope scope.txt --input raw.jsonl                      # reduce a log you already have
raijin-cors --scope scope.txt -l urls.txt --state run.json           # mark findings that are new since last run
raijin-cors --scope scope.txt -l urls.txt --rate 5 --threads 2       # slower
```

`--scope` is required. One rule per line:

```
example.com
*.example.com
10.0.0.0/24
!admin.example.com
```

With no `-u`, `-l` or `--input`, raijin-cors tests every host the scope names: each domain, each IP and each address of a range up to a /24, minus exclusions, as `https://<host>/`. A wildcard or a larger range names no single host, so it gets a `next` step that enumerates it first (`raijin-subs` or `raijin-ports`) and then runs raijin-cors on what was found.

URLs outside the scope are dropped before any request is sent, and observations for out-of-scope URLs in an `--input` log are dropped from the output. Both are counted in `omitted.out_of_scope`. A target without a scheme is tested as `https://`.

Test the endpoints that answer with user data when you are logged in (`/api/me`, `/account`, `/settings`): a CORS hole matters where the browser's cookies unlock something. Pass the session with `-H` if the server only sends CORS headers to logged-in users.

## Output

```json
{
  "tool": "raijin-cors",
  "version": "0.1.0",
  "target": "15 URL(s)",
  "summary": "15 URLs, 121 requests, 12 findings (7 high, 2 medium, 1 low, 2 info), 3 groups, 1 no response",
  "findings": [
    {
      "id": "credentials-8f280142",
      "title": "Any origin reflected with credentials",
      "severity": "high",
      "confidence": "verified",
      "tags": ["credentials", "subdomain"],
      "status": 200,
      "policy": {"reflected+creds": ["reflect", "null", "prefix", "suffix", "dot", "subdomain", "backtick", "underscore"]},
      "locations": ["http://127.0.0.1:19360/api/account"],
      "proof": "curl -si -H 'Origin: https://attacker.example' 'http://127.0.0.1:19360/api/account'"
    },
    {
      "id": "credentials-caade457",
      "title": "null origin allowed with credentials",
      "severity": "high",
      "confidence": "verified",
      "tags": ["credentials"],
      "status": 200,
      "policy": {"reflected+creds": ["null"]},
      "locations": ["http://127.0.0.1:19363/api/account"],
      "proof": "curl -si -H 'Origin: null' 'http://127.0.0.1:19363/api/account'"
    },
    {
      "id": "credentials-baf749fd",
      "title": "Origin check bypassed with credentials (prefix, backtick, underscore)",
      "severity": "high",
      "confidence": "verified",
      "tags": ["credentials"],
      "status": 200,
      "policy": {"reflected+creds": ["prefix", "backtick", "underscore"]},
      "locations": ["http://127.0.0.1:19364/api/account"],
      "proof": "curl -si -H 'Origin: https://127.0.0.1.attacker.example' 'http://127.0.0.1:19364/api/account'"
    },
    {
      "id": "downgrade-cee054c5",
      "title": "http:// origin allowed with credentials on https",
      "severity": "medium",
      "tags": ["downgrade"],
      "status": 200,
      "policy": {"reflected+creds": ["http"]},
      "locations": ["https://127.0.0.1:19373/api/account"],
      "proof": "curl -si -H 'Origin: http://127.0.0.1:19373' 'https://127.0.0.1:19373/api/account'"
    },
    {
      "id": "wildcard-b5d95b36",
      "title": "Wildcard origin",
      "severity": "info",
      "tags": ["wildcard"],
      "status": 200,
      "policy": {"*": ["reflect", "null", "prefix", "suffix", "dot", "subdomain", "backtick", "underscore"]},
      "locations": ["http://127.0.0.1:19369/api/account"],
      "proof": "curl -si -H 'Origin: https://attacker.example' 'http://127.0.0.1:19369/api/account'"
    }
  ],
  "groups": [
    {
      "id": "allowlist-24e59c7d",
      "title": "Attacker origins not allowed",
      "status": 200,
      "policy": {"https://app.example.com+creds": ["reflect", "null", "prefix", "suffix", "dot", "subdomain", "backtick", "underscore"]},
      "locations": ["http://127.0.0.1:19371/api/account"]
    },
    {
      "id": "failed-d79f9e66",
      "title": "No response",
      "policy": {"error: connection refused": ["reflect", "null", "prefix", "suffix", "dot", "subdomain", "backtick", "underscore"]},
      "locations": ["http://127.0.0.1:19399/api/account"]
    },
    {
      "id": "none-bcc105b5",
      "title": "No CORS headers",
      "status": 200,
      "locations": ["http://127.0.0.1:19372/api/account"]
    }
  ],
  "raw": "/root/projects/raijin-cors/bench/fixtures/findings/raw.jsonl"
}
```

That is the real findings run from the benchmark, pretty-printed here with the policy lists on one line. Seven of its twelve findings are left out (the reflect-without-`Vary` copy of the first one, the suffix, dot, backtick/underscore and subdomain bypasses, the reflection without credentials and the wildcard with credentials). The tool writes it as one line.

**Nothing raijin-cors saw is dropped silently.** Every URL is in exactly one finding or group, and every origin test it ran is in that entry's `policy` (or got nothing, the default). Only exact repeats collapse, and they are counted in `omitted.duplicates`.

### The origin tests

Each URL gets one GET per test, with the `Origin` built from its host (without the port, except for `http`). `attacker.example` is a reserved name (RFC 2606): it only appears in the header, no request goes there.

| Test | Origin sent for `https://api.target.com` | What it catches |
|---|---|---|
| `reflect` | `https://attacker.example` | any origin echoed |
| `null` | `null` | `null` allowed (sandboxed iframes, `data:` and `file:` pages send it) |
| `prefix` | `https://api.target.com.attacker.example` | a check that only looks at the start |
| `suffix` | `https://attackerapi.target.com` | a check that only looks at the end |
| `dot` | `https://apixtarget.com` | an unescaped `.` in a regex (skipped when the host has no `.`) |
| `subdomain` | `https://raijin.api.target.com` | every subdomain trusted (exploitable with an XSS or a takeover there) |
| `http` | `http://api.target.com` | an https site that trusts its http origin (exploitable by a network attacker); https URLs only |
| `backtick` | ``https://api.target.com`.attacker.example`` | a parser that stops at `` ` `` (Safari sends this origin) |
| `underscore` | `https://api.target.com_.attacker.example` | a parser that stops at `_` (Chrome and Firefox send this origin) |

Requests are GETs with the `Origin` header (plus any `-H` headers), redirects are not followed (the CORS headers that count are on the response itself), and TLS certificates are not checked. Preflight (`OPTIONS`) requests are not sent.

### What the reducer does

- **One entry per distinct policy.** Two URLs have the same policy when every test got the same outcome, status and `Vary` handling. Each entry lists every URL that has it.
- **`policy`** maps each outcome to the tests that got it, in test order. An outcome is `reflected` (the origin sent came back), `*`, or the literal `Access-Control-Allow-Origin` value, then `+creds` when `Access-Control-Allow-Credentials` is `true` (any other value is written as `+acac=<value>`). A request with no answer is `error: <reason>`. A test that got no CORS headers (`none`) is not listed. When the tests got different HTTP statuses, `status` is left out and each outcome ends in ` (<status>)`.
- **Findings** are the policies that match a rule. Each rule has a fixed severity, and a finding takes the highest:

  | Tag | Severity | Rule |
  |---|---|---|
  | `credentials` | high, `verified` | an attacker origin (`reflect`, `null`, `prefix`, `suffix`, `dot`, `backtick`, `underscore`) is echoed with credentials, or the server answers a literal `null` with credentials. Any page the attacker hosts can read the logged-in user's responses. |
  | `subdomain` | medium | `https://raijin.<host>` is echoed with credentials: exploitable from an XSS or a takeover on any subdomain. |
  | `downgrade` | medium | `http://<host>` is echoed with credentials on an https URL: exploitable by a network attacker who can inject into the plain-http site. |
  | `readable` | low | an attacker origin is echoed without credentials: the attacker reads only what is public, unless the URL is reachable only from the victim's network. |
  | `wildcard` | info | `Access-Control-Allow-Origin: *`. Browsers never send credentials with it, even when `Access-Control-Allow-Credentials: true` is set. |
  | `no-vary` | (adds to another tag) | an origin is echoed without `Origin` in `Vary`, so a shared cache can serve one origin's answer to another. |

  `credentials` findings are `verified`: the server answered the request with those headers. Whether the endpoint returns anything sensitive is for the agent to check with the proof.
- **`proof`** is a `curl` command for the first location and the first test (in test order) behind the finding's highest tag. It does not include your `-H` headers, so no session cookie ends up in the output.
- **Groups** are the policies that match no rule: no CORS headers (`none-…`), a fixed allowlist or a trusted subdomain without credentials (`allowlist-…`), URLs that did not answer (`failed-…`) and URLs where only some requests failed (`partial-…`).
- **Ranking:** findings by severity, then confidence, then the test behind the proof (any origin before `null` before `prefix` ... before `underscore`), then the number of URLs, then `id`. Groups by the number of URLs, then `id`. The same input always gives the same order.
- **`id`** is the highest tag (or the group kind) and a short hash of the policy, so the same policy has the same `id` in the next run.
- **`raw`** is the full per-request JSONL. `--raw <file>` picks the path, and `--input <file>` reduces it again without sending anything.
- **Budget:** `--max-bytes` (16,000 by default) keeps the output bounded. It cuts in this order until the JSON fits:
  1. group locations;
  2. groups;
  3. the locations of the lowest-ranked findings, each keeping one location plus its `count`;
  4. the lowest-ranked findings.

  Every cut is counted in `omitted`, `budget.truncated` is set, and `next` points to the raw file. `--max-items` caps the number of findings (0, the default, keeps all).
- **Errors** say what to try next. A run cut short (Ctrl-C) keeps the requests already answered and says how many were sent.

Fields an agent can rebuild are left out to save tokens:

- the origin of each test (the table above builds it from the URL);
- tests that got no CORS headers (`none`), and `policy` itself when every test got none;
- `status` when the requests got different statuses (each outcome carries its own) or none answered;
- `count`, unless the budget cut `locations`;
- `confidence` when it is `matched` (every finding but `credentials`);
- `omitted`, `errors` and `next` when they are empty;
- `budget` unless something was cut.

The JSON is compact (one line) by default because indentation costs 27% to 46% more tokens in the benchmark; `--pretty` indents it. `--format table` prints a short human view of the same result; it lists finding URLs and proofs but only counts group URLs.

The Raijin banner is **off by default**, so normal runs stay small. `--banner` prints it to **stderr** (never stdout, so the JSON is untouched), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Flags

| Flag | Default | |
|---|---|---|
| `--scope` | (required) | scope file |
| `-u` / `-l` / `--input` | every host the scope names, as `https://<host>/` | one URL (repeatable) / URL file / existing raw JSONL |
| `-H` | | extra request header `Name: value` (repeatable) |
| `--rate` | 10 | requests per second |
| `--threads` | 5 | concurrent requests |
| `--timeout` | 10 | seconds per request |
| `--max-items` | 0 | max findings (0 keeps all) |
| `--max-bytes` | 16000 | max JSON size; cuts are counted in `omitted` |
| `--raw` | temp file | where to save the per-request JSONL |
| `--state` | | state file for new-since-last-run |
| `--format` | json | `json` or `table` |
| `--pretty` | false | indent the JSON |
| `--banner` | false | print the banner to stderr |
| `--version` | | print the version |

Exit codes: `0` when the run worked (with or without findings), `1` on a usage error (no scope, no URL in scope, a bad `-H`, arguments after `--`). The engine is built in, so the `2` (engine missing) of other Raijin tools never happens, and there is nothing to pass after `--`.

## Development

```bash
go test ./...
go vet ./...
LIVE=1 bench/run.sh   # start the local lab and refresh the benchmark fixtures
```

Standard library only. `bench/lab.py` is a local lab with one CORS policy per port; `bench/run.sh` replays the saved fixtures by default.

## Responsible use

Only test what you are authorized to test. The default rate is 10 requests per second; lower it with `--rate` on fragile targets.
