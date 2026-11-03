import asyncio, pathlib, sys, urllib.error, urllib.request, webbrowser
from fastmcp import Client
from fastmcp.client.auth import OAuth
from key_value.aio.stores.filetree import FileTreeStore
from key_value.aio._utils.sanitization import AlwaysHashStrategy
PORT = sys.argv[1] if len(sys.argv) > 1 else "9211"
URL = "http:" + "//127.0.0.1:" + PORT + "/mcp"
STORE = pathlib.Path.home() / "matrix" / "harness" / "fmstore"
SEEN = []
DONE = [False]
class NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
OPENER = urllib.request.build_opener(NoRedir)
def fake_open(url, new=0, autoraise=True):
    SEEN.append(url)
    return True
webbrowser.open = fake_open
def blocking(u):
    loc = ""
    try:
        OPENER.open(u, timeout=10)
        print("NO_LOCATION", flush=True)
        return
    except urllib.error.HTTPError as e:
        loc = e.headers.get("Location") or ""
        print("LOC", loc, flush=True)
    except Exception as e:
        print("ATTEMPT", repr(e), flush=True)
        return
    if not loc:
        return
    try:
        r = urllib.request.urlopen(loc, timeout=10)
        print("CB", r.status, flush=True)
        DONE[0] = True
    except Exception as e:
        print("CBERR", repr(e), flush=True)
async def drive():
    store = FileTreeStore(data_directory=STORE, key_sanitization_strategy=AlwaysHashStrategy())
    auth = OAuth(mcp_url=URL, token_storage=store, callback_port=9301, callback_timeout=40.0)
    async with Client(URL, auth=auth) as c:
        tools = await c.list_tools()
        print("RESULT tools", len(tools), flush=True)
async def fetch():
    for i in range(120):
        if SEEN and not DONE[0]:
            print("DELIVER", i, flush=True)
            await asyncio.to_thread(blocking, SEEN[-1])
        await asyncio.sleep(1.0)
async def main():
    t = asyncio.create_task(drive())
    f = asyncio.create_task(fetch())
    try:
        await asyncio.wait_for(t, timeout=45)
    except Exception as e:
        print("CLIENT ERR", repr(e), flush=True)
    f.cancel()
asyncio.run(main())
