import json, os, sys, anyio
import inspect
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
try:
    from mcp import Client  # mcp 2.x: Client(transport)
except ImportError:  # mcp 1.x
    from mcp import ClientSession as Client
TAKES_TRANSPORT = "server" in inspect.signature(Client.__init__).parameters
from mcp.client.auth import OAuthClientProvider
from mcp.shared.auth import OAuthClientMetadata, OAuthToken, OAuthClientInformationFull
PORT = sys.argv[1] if len(sys.argv) > 1 else "9201"
STATE = os.environ.get("DRIVE_STORE", "state.json")
URL = "http:" + "//127.0.0.1:" + PORT + "/mcp"
ST = []
def dump(x):
    if x is None:
        return None
    if hasattr(x, "model_dump"):
        return x.model_dump(mode="json")
    return x
class Store:
    def boot(self):
        self.tokens = None
        self.info = None
        if os.path.exists(STATE):
            with open(STATE) as f:
                d = json.load(f)
            try:
                self.tokens = OAuthToken.model_validate(d["tokens"]) if d.get("tokens") else None
                self.info = OAuthClientInformationFull.model_validate(d["info"]) if d.get("info") else None
            except Exception as e:
                print("STORE load_failed", repr(e), flush=True)
        return self
    def save(self):
        with open(STATE, "w") as f:
            json.dump({"tokens": dump(self.tokens), "info": dump(self.info)}, f)
    async def get_tokens(self):
        print("STORE get_tokens", bool(self.tokens), flush=True)
        return self.tokens
    async def set_tokens(self, t):
        print("STORE set_tokens", flush=True)
        self.tokens = t
        self.save()
    async def get_client_info(self):
        print("STORE get_client_info", bool(self.info), flush=True)
        return self.info
    async def set_client_info(self, i):
        self.info = i
        self.save()
# FOLLOW_AUTHORIZE=1: request the authorization URL and hand the client the redirect's real
# code/state/iss (authz_response_iss check). Unset: synthesize the code, as the other checks expect.
FOLLOW = os.environ.get("FOLLOW_AUTHORIZE") == "1"
REDIR = {}
async def redirect(u):
    ST.append(u.partition("state=")[2].partition(chr(38))[0])
    print("AUTH_URL", u, flush=True)
    if FOLLOW:
        import urllib.request, urllib.error
        from urllib.parse import urlparse, parse_qs
        class NoFollow(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None
        try:
            urllib.request.build_opener(NoFollow).open(u, timeout=10)
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location", "")
            q = parse_qs(urlparse(loc).query)
            REDIR.update({k: v[0] for k, v in q.items()})
            print("REDIRECT", loc, flush=True)
async def callback():
    state = REDIR.get("state", ST[0] if ST else "")
    code = REDIR.get("code", "fake-code")
    iss = REDIR.get("iss")
    try:  # mcp 2.x returns a typed result (with iss), 1.x a (code, state) tuple (no iss channel)
        from mcp.shared.auth import AuthorizationCodeResult
        fields = getattr(AuthorizationCodeResult, "model_fields", {})
        if "iss" in fields:
            return AuthorizationCodeResult(code=code, state=state, iss=iss)
        return AuthorizationCodeResult(code=code, state=state)
    except ImportError:
        return (code, state)
async def main():
    meta = OAuthClientMetadata(client_name="matrix-probe", redirect_uris=["http:" + "//127.0.0.1:9301/callback"])
    auth = OAuthClientProvider(server_url=URL, client_metadata=meta, storage=Store().boot(), redirect_handler=redirect, callback_handler=callback)
    try:
        async with create_mcp_http_client(auth=auth) as http:
            transport = streamable_http_client(URL, http_client=http)
            if TAKES_TRANSPORT:
                async with Client(transport) as s:
                    print("INITIALIZED", flush=True)
            else:
                async with transport as streams:
                    async with Client(streams[0], streams[1]) as s:
                        await s.initialize()
                        print("INITIALIZED", flush=True)
    except Exception as e:
        print("ENDED", repr(e), flush=True)
anyio.run(main)
