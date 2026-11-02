import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_authscan.tools_digest_probe import report_payload

TOKEN = "fixture-token"
SEEN = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        SEEN.append(self.headers.get("Authorization"))
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if body.get("method") == "tools/list":
            result = {"tools": [{"name": "echo", "description": "echo", "inputSchema": {"type": "object"}}]}
        else:
            result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fixture", "version": "0"}}
        raw = json.dumps({"jsonrpc": "2.0", "id": body.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("mcp-session-id", "fixture-session")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


@pytest.fixture()
def server():
    SEEN.clear()
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd
    httpd.shutdown()


def test_token_reaches_the_server(server):
    url = "http://127.0.0.1:%d/mcp" % server.server_port
    out = report_payload(url, token=TOKEN, allow_private=True, allowed_hosts=["127.0.0.1"])
    assert out.get("captured") is True, out
    assert "Bearer " + TOKEN in [h for h in SEEN if h]


def test_no_token_no_capture(server):
    url = "http://127.0.0.1:%d/mcp" % server.server_port
    out = report_payload(url, allow_private=True, allowed_hosts=["127.0.0.1"])
    assert out.get("captured") is False, out
