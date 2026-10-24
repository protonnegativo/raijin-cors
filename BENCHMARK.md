# Token benchmark: raw request log and curl loop vs raijin-cors

How many tokens does an AI agent spend reading the result of a CORS test, and does it lose anything? This benchmark tests a local lab with every origin test, counts the tokens in each output shape, and checks that every request is in the raijin-cors output.

Reproduce from the saved requests: `bench/run.sh`. Start the lab, retest it and refresh the fixtures first: `LIVE=1 bench/run.sh` (needs curl and openssl; times and latencies will differ, the answers should not).

## Setup

- **Lab:** `bench/lab.py`, one Python process serving small JSON APIs on `127.0.0.1`, ports 19350 to 19399, started by `bench/run.sh` and stopped when it exits. Each port has one CORS policy: none, a fixed allowlist origin, `*`, `*` with credentials, any origin echoed (with credentials, with credentials and no `Vary`, without credentials), `null` allowed, a prefix check, a suffix check, a regex with unescaped dots, trusted subdomains (with and without credentials), a host parser that stops at the first odd character, and an HTTPS site that trusts its http origin. Nothing outside the machine was tested. The run was on 2026-10-24.
- **raijin-cors:** v0.1.0, `--rate 20`, the default 5 threads. Its per-request log (`--raw`) is the fixture: `bench/fixtures/<scenario>/raw.jsonl`, with the URLs in `urls.txt`.
- **There is no external engine.** raijin-cors sends the requests itself, so the "engine output" is its own full log, and the text baseline is what an agent would do without the tool:
  - **raw JSONL:** one line per request, with the time, URL, test, origin, method, status, `Access-Control-Allow-Origin`, `-Credentials`, `-Methods`, `-Headers`, `-Expose-Headers`, `Vary` and the latency. This is the structured output an agent would parse.
  - **curl loop:** for each (URL, Origin) pair in the raw log, a `== <url> Origin: <origin>` line and then `curl -sS -k -D - -o /dev/null -H "Origin: <origin>" <url>`, run right after the live run (`curl.txt`). It prints only the response headers, never the body, which makes it the cheapest honest baseline: an agent that ran `curl -i` would also read every body.
- **raijin-cors rows:** replays of `raw.jsonl` with `--input`, so every row sees the same requests. Defaults apply: no limit on findings, and `--max-bytes 16000`, which was not reached. A replay has no `raw` field; the live runs, which have it, were 16 tokens larger (1,288 and 1,573).
- **Tokens:** counted with tiktoken (`o200k_base`). This is a **proxy**, because Claude's tokenizer is not public. `bench/count_tokens.py` also gives exact Claude counts if `ANTHROPIC_API_KEY` is set and the `anthropic` package is installed. `cl100k_base` gives the same ratios.

## Scenario 1: noisy

46 URLs, 368 requests (8 tests per http URL): 30 API paths with no CORS headers, 8 with a fixed allowlist origin, 4 static files with `*`, 2 paths that trust every https subdomain without credentials, 1 endpoint that echoes any origin with credentials, and 1 port with nothing listening. raijin-cors returned 2 findings (the echoing endpoint, high; the 4 static files, info) and 4 groups (30 with no CORS headers, 8 with the fixed origin, 2 with the trusted subdomain, 1 with no response).

| Output | Bytes | Tokens | vs. raw JSONL |
|---|---:|---:|---:|
| raw JSONL (per-request log) | 80,317 | 30,280 | 1× |
| curl loop (headers only) | 78,792 | 28,850 | 1.05× |
| **raijin-cors JSON (default)** | 3,354 | **1,272** | **24×** |
| raijin-cors `--pretty` | 4,715 | 1,619 | 19× |
| raijin-cors `--format table` | 759 | 241 | 126× |

## Scenario 2: findings

15 URLs, 121 requests: one URL per policy (one of them over HTTPS, so it also gets the `http` test) and 1 port with nothing listening. raijin-cors returned 12 findings and 3 groups:

- high: any origin echoed with credentials (twice: with and without `Vary: Origin`), `null` allowed, the prefix bypass (which the backtick and underscore origins also pass), the suffix bypass, the unescaped dot, and the parser that stops at `` ` `` and `_`;
- medium: every subdomain trusted with credentials, and the https site that trusts `http://`;
- low: any origin echoed without credentials;
- info: `*`, and `*` with credentials;
- groups: the fixed allowlist origin, no CORS headers, no response.

| Output | Bytes | Tokens | vs. raw JSONL |
|---|---:|---:|---:|
| raw JSONL (per-request log) | 26,779 | 9,891 | 1× |
| curl loop (headers only) | 27,633 | 9,659 | 1.02× |
| **raijin-cors JSON (default)** | 5,238 | **1,557** | **6.4×** |
| raijin-cors `--pretty` | 7,916 | 2,272 | 4.4× |
| raijin-cors `--format table` | 2,785 | 866 | 11.4× |

## Nothing is lost

For each scenario, `bench/verify.py` checks every request (a line of `raw.jsonl`) against the raijin-cors output. A request is its URL, its origin test and the Origin it sent, and what came back: `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` (or the error) and the status. The Origin must be the one raijin-cors builds from the URL and the test, the URL must be in exactly one finding or group, and that entry's `policy` must list the test under the request's outcome (or not list it, when it got no CORS headers), with the status on the entry or on the outcome.

- Scenario 1: 368 requests, **0 missing**.
- Scenario 2: 121 requests, **0 missing**.

What the JSON leaves out stays in the raw JSONL: times, latencies, the method, `Vary` (only its effect is kept, as the `no-vary` tag), and `Access-Control-Allow-Methods`, `-Headers` and `-Expose-Headers`.

## Reading the numbers

- **Against the raw log**, the structured output an agent would parse, raijin-cors uses **24× fewer tokens** on the noisy run and **6.4× fewer** on the findings run, for the same requests and answers. The gap grows with repetition: 30 URLs with no CORS headers cost one group and 30 URLs instead of 240 log lines.
- **Against the curl loop**, the result is almost the same, **23× smaller** on the noisy run (28,850 → 1,272) and **6.2× smaller** on the findings run (9,659 → 1,557). Unlike with httpx or nmap, there is no terse text mode to compare with: the loop prints one header block per request, so it is as large as the JSON log. That baseline also leaves the agent to work out, for each of the 121 or 368 answers, whether the origin came back and whether credentials were allowed.
- **The findings run is the least favorable case.** Every URL has a different policy, so nothing collapses across URLs, and each finding pays for its title, tags, policy and proof. The saving there comes from folding nine requests per URL into one policy line.
- **The output stays bounded.** On a test too big for `--max-bytes`, raijin-cors cuts the least important data first: group locations, then groups, then extra locations of low-ranked findings, then low-ranked findings. Every cut is counted in `omitted`, and `next` points to the raw file. The raw log and the curl loop have no upper bound.

## How the default output got here

The first live run of the noisy scenario started sending before the lab had finished starting: the first 4 requests to one URL were refused. The output kept them (that URL got its own group with `error: connection refused` for those 4 tests), which is how the problem was spotted. `bench/run.sh` now waits for the lab to report it is up, the run was repeated, and URLs where only some requests failed got their own group kind (`partial`) and title instead of "Attacker origins not allowed".
