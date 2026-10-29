#!/usr/bin/env python3
import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
HITS = []
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        return
    def do_GET(self):
        if self.path.startswith("/mcp"):
            self.send_response(401)
            self.send_header("www-authenticate", 'Bearer resource_metadata="http://127.0.0.1:8765/.well-known/oauth-protected-resource"')
            self.end_headers()
            return
        if "oauth-protected-resource" in self.path:
            body = json.dumps({"resource": "http://127.0.0.1:8765/mcp", "authorization_servers": ["http://127.0.0.1:8765"]}).encode()
        else:
            body = json.dumps({"issuer": "http://127.0.0.1:8765", "token_endpoint": "http://127.0.0.1:8765/token"}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        self.rfile.read(n)
        HITS.append(self.path)
        self.send_response(400)
        self.send_header("cache-control", "no-store")
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error": "invalid_grant"}')
def serve():
    HTTPServer(("127.0.0.1", 8765), H).serve_forever()
class Mem:
    def __init__(self):
        self.tokens = None
        self.info = None
    async def get_tokens(self):
        return self.tokens
    async def set_tokens(self, tokens):
        self.tokens = tokens
    async def get_client_info(self):
        return self.info
    async def set_client_info(self, info):
        self.info = info
def run(bound):
    HITS.clear()
    import anyio, httpx2
    from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
    kw = dict(server_url="http://127.0.0.1:8765/mcp", storage=Mem(), client_id="svc", client_secret="not-a-real-secret")
    if bound:
        kw["issuer"] = "https://legit.example"
    p = ClientCredentialsOAuthProvider(**kw)
    async def once():
        async with httpx2.AsyncClient(auth=p) as c:
            await c.get("http://127.0.0.1:8765/mcp")
    try:
        anyio.run(once)
        err = "none"
    except Exception as e:
        err = type(e).__name__
    return err, any(x.endswith("/token") for x in HITS)
if __name__ == "__main__":
    threading.Thread(target=serve, daemon=True).start()
    print("bound", *run(True))
    print("unbound", *run(False))
