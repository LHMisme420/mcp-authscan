import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
if MODE not in ("unauth", "auth"):
    sys.exit('usage: h4b.py "unauth"|"auth"')

URL = "http://127.0.0.1:8765/mcp"
PROBE_TOOL = {
    "name": "probe_ping",
    "description": "returns pong",
    "inputSchema": {"type": "object", "properties": {}},
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/mcp":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        method = req.get("method")
        rid = req.get("id")
        print(f"REQ {method}", flush=True)
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "h4b", "version": "0.0.1"},
            }
        elif method == "tools/list":
            result = {"tools": [] if MODE == "unauth" else [PROBE_TOOL]}
        elif method == "tools/call" and (req.get("params") or {}).get("name") == "probe_ping":
            result = {"content": [{"type": "text", "text": "pong"}]}
        else:
            result = {}
        self._json({"jsonrpc": "2.0", "id": rid, "result": result})


def serve():
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()


def _text(res):
    content = getattr(res, "content", res)
    if isinstance(content, list):
        return " ".join(getattr(c, "text", str(c)) for c in content)
    return str(content)


async def main():
    threading.Thread(target=serve, daemon=True).start()
    await asyncio.sleep(0.3)
    try:
        from fastmcp import Client
        from fastmcp.client.auth import BearerAuth
        if MODE == "auth":
            client = Client(URL, auth=BearerAuth(token="synthetic-token"))
        else:
            client = Client(URL)
        async with client:
            try:
                tools = await client.list_tools()
                print(f"RESULT tools {len(tools)} {' '.join(sorted(t.name for t in tools))}", flush=True)
            except Exception as e:
                print(f"RESULT tools exception {type(e).__name__} {e}", flush=True)
            try:
                res = await client.call_tool("probe_ping", {})
                print(f"RESULT call {_text(res)}", flush=True)
            except Exception as e:
                print(f"RESULT call exception {type(e).__name__} {e}", flush=True)
    except Exception as e:
        print(f"RESULT exception {type(e).__name__} {e}", flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except BaseException as e:
        print(f"RESULT exception {type(e).__name__} {e}", flush=True)
    sys.exit(0)
