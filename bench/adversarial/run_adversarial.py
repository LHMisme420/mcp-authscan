"""Category 4: adversarial conditions. Declared expectations first, run second.

Each case is a hostile server on loopback. The runner reports MATCH when the
scanner did what the case declares, DIVERGENCE otherwise. A DIVERGENCE is a
question about the tool, never an assertion that the tool is wrong.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(file))))
HOP = "http://elsewhere.example/mcp"

def jrpc(payload):
return json.dumps(payload).encode()

class Silent(BaseHTTPRequestHandler):
protocol_version = "HTTP/1.1"

def log_message(self, *a):
    pass

def send(self, code, body=b"", headers=None):
    self.send_response(code)
    for k, v in (headers or {}).items():
        self.send_header(k, v)
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

def body(self):
    n = int(self.headers.get("Content-Length") or 0)
    return self.rfile.read(n)

def do_GET(self):
    self.send(405, b"")
def redirecthandler(): class H(Silent): def doPOST(self):
self.body()
self.send(302, b"", {"Location": HOP})
return H

def htmlhandler(): class H(Silent): def doPOST(self):
self.body()
self.send(200, b"

hello
",
{"Content-Type": "text/html"})
return H
def auth401handler(): class H(Silent): def doPOST(self):
self.body()
self.send(401, b"")
return H

def invalidparamshandler():
"""Open handshake, tool call rejected for missing arguments, not for auth."""
class H(Silent):
def doPOST(self): raw = self.body() try: doc = json.loads(raw or b"{}") except ValueError: doc = {} method = doc.get("method") or "" ident = doc.get("id", 1) if method == "initialize": self.send(200, jrpc({"jsonrpc": "2.0", "id": ident, "result": { "protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "adv", "version": "0"}}}), {"Content-Type": "application/json"}) elif method == "tools/list": self.send(200, jrpc({"jsonrpc": "2.0", "id": ident, "result": {"tools": [ {"name": "listitems", "description": "List items",
"inputSchema": {"type": "object"}}]}}),
{"Content-Type": "application/json"})
elif method == "tools/call":
self.send(200, jrpc({"jsonrpc": "2.0", "id": ident, "error": {
"code": -32602, "message": "Invalid params"}}),
{"Content-Type": "application/json"})
else:
self.send(200, jrpc({"jsonrpc": "2.0", "id": ident, "result": {}}),
{"Content-Type": "application/json"})
return H

CASES = [
("redirect-cross-host", redirecthandler(), [], 6, ["redirect refused"], []), ("html-200", htmlhandler(), [],
5, ["PREFLIGHT CHECK: FAILED"], ["ZERO-AUTH"]),
("401-no-challenge", auth401handler(), [], 5, [], ["ZERO-AUTH"]), ("invalid-params-probe", invalidparams_handler(), ["--allow-host", "HOST"],
5, ["ZERO-AUTH"], []),
]

def runcase(name, handler, extra, expectexit, expectin, expectabsent):
srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
port = srv.serveraddress[1] threading.Thread(target=srv.serveforever, daemon=True).start()
host = "127.0.0.1:%d" % port
cmd = [sys.executable, "-m", "mcpauthscan.monolith", "http://" + host + "/mcp", "--contact", "bench@example.invalid", "--authorized-by", "bench", "--auth-basis", "self-written adversarial fixture on loopback", "--allow-private"] + [a.replace("HOST", host) for a in extra] try: p = subprocess.run(cmd, cwd=REPO, captureoutput=True, text=True, timeout=120)
out, code = p.stdout + p.stderr, p.returncode
except subprocess.TimeoutExpired:
out, code = "TIMEOUT", -1
finally:
srv.shutdown()
srv.server_close()

problems = []
if code != expect_exit:
    problems.append("exit %s, declared %s" % (code, expect_exit))
for s in expect_in:
    if s.lower() not in out.lower():
        problems.append("missing %r" % s)
for s in expect_absent:
    if s.lower() in out.lower():
        problems.append("unexpected %r" % s)

print("%-22s %s" % (name, "MATCH" if not problems else "DIVERGENCE"))
if problems:
    for pr in problems:
        print("   " + pr)
    for line in [l for l in out.splitlines() if l.strip()][-12:]:
        print("   | " + line)
return not problems
def main():
results = [run_case(*c) for c in CASES]
print("")
print("%d of %d cases matched" % (sum(results), len(results)))
return 0 if all(results) else 1

if name == "main":
sys.exit(main())
