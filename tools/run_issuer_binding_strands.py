"""Issuer-binding check for the Strands Agents SDK MCP client."""
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = sys.argv[1] if len(sys.argv) > 1 else "mismatched"
CAPTURED = []
HITS = []
SRV_HITS = []


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


AS_PORT = free_port()
SRV_PORT = free_port()


def build(kind, port):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, code, obj, extra=None):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            HITS.append(("GET", kind, self.path))
            if kind == "as" and self.path == "/.well-known/oauth-authorization-server":
                issuer = "http://127.0.0.1:%d" % port
                if MODE == "mismatched":
                    issuer = "http://decoy-issuer.invalid"
                self.reply(200, {
                    "issuer": issuer,
                    "authorization_endpoint": "http://127.0.0.1:%d/authorize" % port,
                    "token_endpoint": "http://127.0.0.1:%d/token" % port,
                    "registration_endpoint": "http://127.0.0.1:%d/register" % port,
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["client_credentials"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
                })
                return
            if kind == "srv" and self.path == "/.well-known/oauth-protected-resource":
                SRV_HITS.append(self.path)
                self.reply(200, {
                    "resource": "http://127.0.0.1:%d/mcp" % port,
                    "authorization_servers": ["http://127.0.0.1:%d" % AS_PORT],
                })
                return
            self.reply(404, {"error": "not_found", "path": self.path})

        def do_POST(self):
            HITS.append(("POST", kind, self.path))
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace")
            if kind == "as" and self.path == "/token":
                entry = {"auth_header": self.headers.get("Authorization"), "body": raw}
                CAPTURED.append(entry)
                print("TOKEN HIT:", json.dumps(entry)[:400])
                self.reply(200, {"access_token": "decoy", "token_type": "Bearer", "expires_in": 60})
                return
            if kind == "srv" and self.path == "/mcp":
                SRV_HITS.append(self.path)
                self.reply(401, {"error": "unauthorized"}, {
                    "WWW-Authenticate": 'Bearer resource_metadata="http://127.0.0.1:%d/.well-known/oauth-protected-resource"' % port,
                })
                return
            self.reply(404, {"error": "not_found"})

    return H


def serve(port, handler):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


serve(AS_PORT, build("as", AS_PORT))
serve(SRV_PORT, build("srv", SRV_PORT))

from strands.tools.mcp import MCPClient

URL = "http://127.0.0.1:%d/mcp" % SRV_PORT
client = MCPClient(url=URL, auth={"client_id": "probe-client", "client_secret": "PROBE-SECRET-1234"})

try:
    with client.start():
        client.list_tools_sync()
except Exception as e:
    print("DRIVE STOP:", str(type(e)), str(e)[:300])

print("HITS:", HITS)
print("server hits:", len(SRV_HITS), "token hits:", len(CAPTURED))

if not SRV_HITS:
    print("NOT_PROBED: the client never reached the MCP server, so nothing was tested.")
    sys.exit(2)

if MODE == "consistent":
    if CAPTURED:
        print("PASS (control): client sent credentials to the matching issuer, chain works.")
        sys.exit(0)
    print("EXCLUDED: no credential reached the decoy in consistent mode, so mismatched proves nothing.")
    sys.exit(3)

if CAPTURED:
    print("FAIL: client sent client_id/client_secret to a token endpoint whose issuer did not match the URL it was fetched from.")
    sys.exit(1)

print("PASS: no credential-bearing request reached the decoy token endpoint.")
sys.exit(0)
