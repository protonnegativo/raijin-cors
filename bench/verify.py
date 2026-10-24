"""Checks that every request in a raijin-cors raw log is in a raijin-cors result.

A result is one raw line: the URL, the origin test and the Origin it sent, and what came back: the
Access-Control-Allow-Origin and Access-Control-Allow-Credentials values (or the error) and the HTTP
status. For each line:

- the Origin must be the one raijin-cors builds for that URL and test (so the agent can rebuild it);
- the URL must be in the locations of exactly one finding or group;
- that entry's policy must list the test under the line's outcome ("none" is the default and is not
  listed), and the status must be the entry's status or, when the entry has none, written after the
  outcome as " (<status>)".

usage: python verify.py <raw.jsonl> <raijin.json>
"""
import json, sys
from urllib.parse import urlsplit

raw, out = sys.argv[1], sys.argv[2]
o = json.load(open(out))
ATTACKER = "attacker.example"


def origin_for(url, test):
    u = urlsplit(url)
    host = (u.hostname or "").lower()
    if ":" in host:
        host = "[" + host + "]"
    return {
        "reflect": "https://" + ATTACKER,
        "null": "null",
        "prefix": "https://" + host + "." + ATTACKER,
        "suffix": "https://attacker" + host,
        "dot": "https://" + host.replace(".", "x", 1) if "." in host else None,
        "subdomain": "https://raijin." + host,
        "http": "http://" + u.netloc.lower() if u.scheme == "https" else None,
        "backtick": "https://" + host + "`." + ATTACKER,
        "underscore": "https://" + host + "_." + ATTACKER,
    }[test]


def outcome(e):
    if e.get("error"):
        return "error: " + e["error"]
    acao, acac = (e.get("acao") or "").strip(), (e.get("acac") or "").strip()
    s = "none" if not acao else ("reflected" if acao == e["origin"] else acao)
    if acac == "true":
        s += "+creds"
    elif acac:
        s += "+acac=" + acac
    return s


where = {}
for kind in ("findings", "groups"):
    for x in o[kind]:
        for loc in x.get("locations", []):
            where.setdefault(loc, []).append(x)

miss, n = [], 0
for line in open(raw):
    line = line.strip()
    if not line.startswith("{"):
        continue
    e = json.loads(line)
    n += 1
    why = None
    entries = where.get(e["url"], [])
    if origin_for(e["url"], e["test"]) != e["origin"]:
        why = "origin is not the one raijin-cors builds"
    elif len(entries) != 1:
        why = f"URL is in {len(entries)} entries"
    else:
        x = entries[0]
        k = outcome(e)
        status = e.get("status") or 0
        if x.get("status"):
            if status and status != x["status"]:
                why = f"status {status} != {x['status']}"
        elif status:
            k += f" ({status})"
        if not why and k != "none" and e["test"] not in x.get("policy", {}).get(k, []):
            why = f"policy has no {k!r} for {e['test']}"
        if not why and k == "none" and any(e["test"] in v for v in x.get("policy", {}).values()):
            why = "test is listed although it got none"
    if why:
        miss.append((e["url"], e["test"], why))
print(f"{n} requests, {len(miss)} missing from output", "truncated" if o.get("budget") else "")
for m in miss[:5]:
    print("  MISSING", m)
