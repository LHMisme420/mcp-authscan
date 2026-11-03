import json, os, sys, anyio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
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
async def redirect(u):
    ST.append(u.partition("state=")[2].partition(chr(38))[0])
    print("AUTH_URL", u, flush=True)
async def callback():
    return ("fake-code", ST[0] if ST else "")
async def main():
    meta = OAuthClientMetadata(client_name="matrix-probe", redirect_uris=["http:" + "//127.0.0.1:9301/callback"])
    auth = OAuthClientProvider(server_url=URL, client_metadata=meta, storage=Store().boot(), redirect_handler=redirect, callback_handler=callback)
    try:
        async with streamablehttp_client(URL, auth=auth) as (r, w, x):
            async with ClientSession(r, w) as s:
                await s.initialize()
                print("INITIALIZED", flush=True)
    except Exception as e:
        print("ENDED", repr(e), flush=True)
anyio.run(main)
