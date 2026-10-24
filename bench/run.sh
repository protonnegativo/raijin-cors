#!/usr/bin/env bash
# Reproducible token benchmark: raijin-cors's full request log and a curl loop vs raijin-cors output.
#
# usage: bench/run.sh [workdir]
#        LIVE=1 bench/run.sh [workdir]   start the local lab, retest it and refresh bench/fixtures first
# needs: go, python3 with tiktoken (pip install tiktoken); LIVE=1 also needs curl and openssl
# optional: ANTHROPIC_API_KEY + pip install anthropic for exact Claude token counts
# env: PY=<python with tiktoken>
#
# Safety: LIVE=1 tests only the lab it starts itself (bench/lab.py) on 127.0.0.1, ports 19350-19399, at
# 20 requests per second. It stops the lab when it exits.
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
PY=${PY:-python3}
mkdir -p "$W"
echo "workdir: $W"

# Lab: one python process, one CORS policy per port (see lab.py for the policies).
# noisy:    46 URLs. 30 API paths with no CORS headers, 8 with a fixed allowlist origin, 4 static files
#           with *, 2 paths that trust every https subdomain without credentials, 1 endpoint that
#           reflects any origin with credentials, and 1 port with nothing listening.
# findings: one URL per policy, 15 of them, one over HTTPS, and 1 port with nothing listening.
lab=(19350=none 19351=fixed 19352=wildcard 19353=reflect-creds 19354=subdomain
  19360=reflect-creds 19361=reflect-novary 19362=reflect 19363=null-creds 19364=prefix-creds
  19365=suffix-creds 19366=dot-creds 19367=subdomain-creds 19368=chars-creds 19369=wildcard
  19370=wildcard-creds 19371=fixed 19372=none 19373=downgrade-creds:tls)
noisy=()
for i in $(seq 1 30); do noisy+=("http://127.0.0.1:19350/api/v1/items/$i"); done
for i in $(seq 1 8); do noisy+=("http://127.0.0.1:19351/api/v1/orders/$i"); done
for f in app.js app.css logo.svg fonts.css; do noisy+=("http://127.0.0.1:19352/static/$f"); done
noisy+=(http://127.0.0.1:19354/api/v1/profile http://127.0.0.1:19354/api/v1/settings)
noisy+=(http://127.0.0.1:19353/api/v1/me http://127.0.0.1:19355/api/v1/health)
findings=()
for p in $(seq 19360 19372); do findings+=("http://127.0.0.1:$p/api/account"); done
findings+=(https://127.0.0.1:19373/api/account http://127.0.0.1:19399/api/account)
printf '127.0.0.1\n' > "$W/scope.txt"

(cd "$ROOT" && go build -o "$W/raijin-cors" ./cmd/raijin-cors)

if [ "${LIVE:-}" = 1 ]; then
  for spec in "${lab[@]}" 19355= 19399=; do
    port=${spec%%=*}
    if ss -ltn | grep -q ":$port "; then echo "port $port is busy; free it first" >&2; exit 1; fi
  done
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 \
    -keyout "$W/key.pem" -out "$W/cert.pem" 2> /dev/null
  CERT=$W/cert.pem KEY=$W/key.pem python3 "$HERE/lab.py" "${lab[@]}" > "$W/lab.log" 2>&1 &
  echo $! > "$W/pids"
  trap '[ -f "$W/pids" ] && xargs kill < "$W/pids" 2>/dev/null || true' EXIT
  for _ in $(seq 50); do grep -q "servers up" "$W/lab.log" && break; sleep 0.1; done
  grep -q "servers up" "$W/lab.log" || { echo "lab did not start: $(cat "$W/lab.log")" >&2; exit 1; }
  for name in noisy findings; do
    f=$HERE/fixtures/$name
    mkdir -p "$f"
    eval 'printf "%s\n" "${'$name'[@]}"' > "$f/urls.txt"
    # raijin-cors sends every origin test and saves its per-request log as raw: that file is the fixture.
    "$W/raijin-cors" --scope "$W/scope.txt" -l "$f/urls.txt" --rate 20 --raw "$f/raw.jsonl" > "$W/$name.live.json"
    # The same requests as an agent would send them by hand: one curl per (URL, Origin), headers only.
    python3 -c 'import json,sys
for l in open(sys.argv[1]):
    e = json.loads(l)
    print(e["url"] + "\t" + e["origin"])' "$f/raw.jsonl" | while IFS=$'\t' read -r url origin; do
      echo "== $url Origin: $origin"
      curl -sS -k -D - -o /dev/null -H "Origin: $origin" "$url" 2>&1 || true
      sleep 0.05
    done > "$f/curl.txt"
  done
fi

scenario() {
  local name=$1
  local f=$HERE/fixtures/$name o=$W/$name
  mkdir -p "$o"
  # raijin-cors replays raw with --input, so every row sees the same requests and answers.
  (cd "$ROOT" && "$W/raijin-cors" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl") > "$o/raijin.json"
  (cd "$ROOT" && "$W/raijin-cors" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --pretty) > "$o/raijin_pretty.json"
  (cd "$ROOT" && "$W/raijin-cors" --scope "$W/scope.txt" --input "bench/fixtures/$name/raw.jsonl" --format table) > "$o/raijin_table.txt"
  echo; echo "## $name: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["summary"])' "$o/raijin.json")"; echo
  python3 "$HERE/verify.py" "$f/raw.jsonl" "$o/raijin.json"
  "$PY" "$HERE/count_tokens.py" \
    "raw JSONL (per-request log)=$f/raw.jsonl" \
    "curl -D - loop (headers only)=$f/curl.txt" \
    "raijin-cors JSON (default)=$o/raijin.json" \
    "raijin-cors --pretty=$o/raijin_pretty.json" \
    "raijin-cors --format table=$o/raijin_table.txt"
}

scenario noisy
scenario findings
