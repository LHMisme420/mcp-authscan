"""Loopback MCP server for evidence tests and the two-run demo.

The server's surface is a mutable ``config`` dict, so a caller can change
what it exposes between two scans:

    config = {
        "token": "t0k",                 # bearer token for the authenticated view (None: no auth view)
        "anonymous_tools": ["list_docs"],
        "authenticated_tools": ["list_docs", "write_doc"],
        "prompts": [], "resources": [],
        "gate_initialize": False,       # True: anonymous initialize answers 401
    }

Every request with the right bearer token sees ``authenticated_tools``;
everything else sees ``anonymous_tools``.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DEFAULT_CONFIG = {
    "token": None,
    "anonymous_tools": [],
    "authenticated_tools": [],
    "prompts": [],
    "resources": [],
    "gate_initialize": False,
}


def _tool(name):
    return {"name": name, "description": f"{name} tool", "inputSchema": {"type": "object"}}


def make_handler(config):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, obj, code=200):
            body = b"" if obj is None else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authenticated(self):
            token = config.get("token")
            return bool(token) and self.headers.get("Authorization") == f"Bearer {token}"

        def do_POST(self):
            try:
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            except ValueError:
                msg = {}
            method, mid = msg.get("method"), msg.get("id")
            authed = self._authenticated()
            if config.get("gate_initialize") and not authed:
                self._send({"error": "unauthorized"}, 401)
                return
            if method == "initialize":
                self._send({"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "evidence-fixture", "version": "0"}, "instructions": "x" * 900}})
            elif method == "tools/list":
                names = config["authenticated_tools"] if authed else config["anonymous_tools"]
                self._send({"jsonrpc": "2.0", "id": mid, "result": {"tools": [_tool(n) for n in names]}})
            elif method == "prompts/list":
                self._send({"jsonrpc": "2.0", "id": mid, "result": {"prompts": [{"name": n} for n in config["prompts"]]}})
            elif method == "resources/list":
                self._send({"jsonrpc": "2.0", "id": mid, "result": {"resources": [{"uri": u} for u in config["resources"]]}})
            elif mid is None:
                self._send(None, 202)
            else:
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "not found"}})

        def do_GET(self):
            self._send({"error": "not found"}, 404)

        def log_message(self, *args):
            pass
    return Handler


class FixtureServer:
    """Context manager: ``with FixtureServer(**cfg) as (url, config): ...``"""

    def __init__(self, **overrides):
        self.config = dict(DEFAULT_CONFIG, **overrides)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(self.config))

    def __enter__(self):
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/mcp", self.config

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
