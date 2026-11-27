import asyncio
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
if MODE not in ("401", "empty"):
    sys.exit('usage: h4.py "401"|"empty"')


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
            self._json({"jsonrpc": "2.0", "id": rid, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "serverInfo": {"name": "h4", "version": "0.0.1"}}})
        elif method == "tools/list" and MODE == "401":
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif method == "tools/list" and MODE == "empty":
            self._json({"jsonrpc": "2.0", "id": rid, "result": {"tools": []}})
        else:
            self._json({"jsonrpc": "2.0", "id": rid, "result": {}})


def serve():
    HTTPServer(("127.0.0.1", 8765), Handler).serve_forever()


async def main():
    threading.Thread(target=serve, daemon=True).start()
    await asyncio.sleep(0.3)
    from fastmcp import Client
    try:
        async with Client("http://127.0.0.1:8765/mcp") as client:
            tools = await client.list_tools()
            print(f"RESULT tools {len(tools)}", flush=True)
    except Exception as e:
        print(f"RESULT exception {type(e).__name__} {e}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
