import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
MODE = sys.argv[1]
PORT = int(sys.argv[2])
BASE = "http:" + "//127.0.0.1:" + str(PORT)
FOREIGN = "http:" + "//127.0.0.1:9999"
LOGDIR = os.environ.get("FIXTURE_LOGDIR", "logs")
os.makedirs(LOGDIR, exist_ok=True)
LOG = os.path.join(LOGDIR, str(PORT) + ".jsonl")
def issuer():
    if MODE == "badmeta":
        return FOREIGN
    return BASE
def log(rec):
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")
class H(BaseHTTPRequestHandler):
    def j(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def noauth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer resource_metadata=\"" + BASE + "/.well-known/oauth-authorization-server\"")
        self.send_header("Content-Length", "0")
        self.end_headers()
    def mcp(self, raw):
        if not self.headers.get("Authorization"):
            self.noauth()
            return
        rid = 1
        meth = ""
        try:
            meth = json.loads(raw).get("method", "") if raw else ""
        except Exception:
            meth = ""
        try:
            rid = json.loads(raw).get("id", 1) if raw else 1
        except Exception:
            rid = 1
        if meth == "tools/list":
            self.j(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "echo", "description": "Echo the input back", "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}}}, {"name": "add", "description": "Add two integers", "inputSchema": {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}}}]}})
            return
        self.j(200, {"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "fixture", "version": "0"}}})
    def do_GET(self):
        u = urlparse(self.path)
        log({"m": "GET", "p": u.path, "q": u.query, "auth": self.headers.get("Authorization", "")})
        if u.path == "/mcp":
            self.mcp("")
            return
        if u.path == "/.well-known/oauth-authorization-server":
            self.j(200, {"issuer": issuer(), "authorization_endpoint": BASE + "/authorize", "token_endpoint": BASE + "/token", "registration_endpoint": BASE + "/register", "code_challenge_methods_supported": ["S256"], "token_endpoint_auth_methods_supported": ["none"], "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"]})
            return
        if u.path == "/authorize":
            st = ""
            for part in u.query.split(chr(38)):
                if part.startswith("state="):
                    st = part[6:]
            self.send_response(302)
            if MODE == "badauthiss":
                st = st + chr(38) + "iss=" + FOREIGN
            self.send_header("Location", "http:" + "//localhost:9301/callback?code=abc123" + chr(38) + "state=" + st)
            self.end_headers()
            return
        self.j(404, {"error": "not_found"})
    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(n).decode() if n else ""
        log({"m": "POST", "p": u.path, "auth": self.headers.get("Authorization", ""), "body": raw[:400]})
        if u.path == "/mcp":
            self.mcp(raw)
            return
        if u.path == "/register":
            self.j(201, {"client_id": "cid-" + str(PORT), "client_secret": "sec-" + str(PORT), "redirect_uris": ["http:" + "//127.0.0.1:9301/callback"], "token_endpoint_auth_method": "none"})
            return
        if u.path == "/token":
            body = {"access_token": "at-" + MODE + "-" + str(PORT), "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt-" + MODE + "-" + str(PORT)}
            if MODE == "strict" and "resource=" not in raw:
                self.j(400, {"error": "invalid_target"})
                return
            if MODE == "badtoken":
                body["iss"] = FOREIGN
            self.j(200, body)
            return
        self.j(404, {"error": "not_found"})
    def log_message(self, fmt, *args):
        pass
srv = HTTPServer(("127.0.0.1", PORT), H)
print("listening", MODE, PORT, issuer(), flush=True)
srv.serve_forever()
