"""Local lab for the raijin-cors benchmark: small HTTP servers on 127.0.0.1, one process.

Each argument is port=policy, or port=policy:tls for HTTPS (needs CERT and KEY in the environment).
Every path answers 200 with a small JSON body; the policy decides the CORS headers from the Origin
the request sent. The policies are the misconfigurations (and the safe setups) seen in the wild:

  none             no CORS headers
  fixed            Access-Control-Allow-Origin: https://app.example.com, with credentials, whatever was sent
  wildcard         Access-Control-Allow-Origin: *
  wildcard-creds   * with Access-Control-Allow-Credentials: true (browsers refuse it)
  reflect          any origin echoed, no credentials
  reflect-creds    any origin echoed with credentials, Vary: Origin
  reflect-novary   any origin echoed with credentials, no Vary
  null-creds       "null" (and the site's own origin) allowed with credentials
  prefix-creds     origins that start with https?://127.0.0.1 allowed with credentials
  suffix-creds     origins that end with 127.0.0.1 allowed with credentials
  dot-creds        ^https?://127.0.0.1(:port)?$ with the dots unescaped, with credentials
  subdomain        any https subdomain of 127.0.0.1 allowed, no credentials
  subdomain-creds  any https subdomain of 127.0.0.1 allowed with credentials
  chars-creds      the origin host is read up to the first character that is not [a-z0-9.-], with credentials
  downgrade-creds  http and https origins of 127.0.0.1 allowed with credentials (an HTTPS site)

usage: python3 lab.py 19350=none 19353=reflect-creds 19373=downgrade-creds:tls ...
"""
import os
import re
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = "127.0.0.1"


def allow(origin, creds=True, vary=True):
    h = [("Access-Control-Allow-Origin", origin)]
    if creds:
        h.append(("Access-Control-Allow-Credentials", "true"))
    if vary:
        h.append(("Vary", "Origin"))
    return h


def chars_host(origin):
    m = re.match(r"^https?://([a-z0-9.-]+)", origin)
    return m.group(1) if m else ""


def policy(kind, origin, own):
    if not origin:
        return []
    if kind == "none":
        return []
    if kind == "fixed":
        return [("Access-Control-Allow-Origin", "https://app.example.com"), ("Access-Control-Allow-Credentials", "true")]
    if kind == "wildcard":
        return [("Access-Control-Allow-Origin", "*")]
    if kind == "wildcard-creds":
        return [("Access-Control-Allow-Origin", "*"), ("Access-Control-Allow-Credentials", "true")]
    ok = {
        "reflect": True,
        "reflect-creds": True,
        "reflect-novary": True,
        "null-creds": origin in ("null", own),
        "prefix-creds": re.match(r"^https?://127\.0\.0\.1", origin) is not None,
        "suffix-creds": origin.endswith("127.0.0.1"),
        "dot-creds": re.match(r"^https?://127.0.0.1(:\d+)?$", origin) is not None,
        "subdomain": re.match(r"^https://([a-z0-9-]+\.)+127\.0\.0\.1$", origin) is not None,
        "subdomain-creds": re.match(r"^https://([a-z0-9-]+\.)+127\.0\.0\.1$", origin) is not None,
        "chars-creds": chars_host(origin) == HOST,
        "downgrade-creds": re.match(r"^https?://127\.0\.0\.1(:\d+)?$", origin) is not None,
    }[kind]
    if not ok:
        return []
    return allow(origin, creds=kind not in ("reflect", "subdomain"), vary=kind != "reflect-novary")


def handler(kind, own):
    class H(BaseHTTPRequestHandler):
        server_version = "nginx"
        sys_version = ""

        def do_GET(self):
            data = b'{"user":"alice","email":"alice@example.com"}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            for k, v in policy(kind, self.headers.get("Origin", ""), own):
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    return H


def main():
    servers = []
    for arg in sys.argv[1:]:
        port, kind = arg.split("=", 1)
        tls = kind.endswith(":tls")
        kind = kind.removesuffix(":tls")
        own = f"{'https' if tls else 'http'}://{HOST}:{port}"
        s = ThreadingHTTPServer((HOST, int(port)), handler(kind, own))
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(os.environ["CERT"], os.environ["KEY"])
            s.socket = ctx.wrap_socket(s.socket, server_side=True)
        servers.append(s)
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print(f"lab: {len(servers)} servers up", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
