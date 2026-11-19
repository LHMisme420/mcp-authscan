import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

INITIALIZE = {
    "protocolVersion": "2025-06-18",
    "capabilities": {"tools": {"listChanged": True}},
    "serverInfo": {"name": "zeroauth-fixture", "version": "0.0.1"},
    "instructions": "x".ljust(900, "x"),
}


class _H(BaseHTTPRequestHandler):
    """A zero-auth MCP server that exposes no tools.

    Until 2026-11-19 this answered every POST with the same initialize result and no JSON-RPC
    envelope, and GET with the default 501. c573ea0 (2026-11-15) grades zero-auth only on a
    JSON-RPC reply, on purpose (an HTML page or a bare JSON document is not an MCP answer), so
    this fixture stopped being an MCP server to the scanner and the test failed. It now answers
    per method with jsonrpc and the request id, an empty tools list, 202 for notifications and
    404 for GET, like the sample-report fixture.
    """
    def _send(self, obj, code=200):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            msg = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            msg = {}
        method, rid = msg.get("method"), msg.get("id")
        if method == "initialize":
            self._send({"jsonrpc": "2.0", "id": rid, "result": INITIALIZE})
        elif method == "tools/list":
            self._send({"jsonrpc": "2.0", "id": rid, "result": {"tools": []}})
        elif method in ("prompts/list", "resources/list"):
            self._send({"jsonrpc": "2.0", "id": rid, "result": {method.split("/")[0]: []}})
        elif rid is None:
            self._send(None, 202)
        else:
            self._send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}})

    def do_GET(self):
        self._send({"error": "not found"}, 404)

    def log_request(self, code="-", size="-"):
        pass

    def log_message(self, fmt, a1="", a2="", a3=""):
        pass


@pytest.fixture
def zeroauth_server():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield "http://127.0.0.1:%d/mcp" % srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def test_zero_auth_reported_with_evidence(tmp_path, zeroauth_server):
    out = tmp_path / "report.json"
    argv = [
        zeroauth_server,
        "--allow-private", "--json", "--output", str(out),
        "--contact", "test@example.com",
        "--authorized-by", "Test",
        "--auth-basis", "local fixture",
        "--scope", "fixture",
    ]
    runner = "import sys; from mcp_authscan.monolith import main; sys.argv = ['mcp-authscan'] + sys.argv[1:]; main()"
    proc = subprocess.run(
        [sys.executable, "-c", runner] + argv,
        capture_output=True, text=True, timeout=120,
    )
    # A no-tools zero-auth finding is MEDIUM under calibration 2026.11.07.1, below the
    # default fail threshold, so the scan exits 0. (Was exit 1 when zero-auth was CRITICAL.)
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text())
    assert data["exit_condition"] != "finding_at_or_above_high"
    assert data["discovery_status"] == "ZERO_AUTH_DETECTED"
    assert data["severity_calibration_version"] == "2026.11.07.1"
    hits = [f for f in data["findings"] if f["rule"] == "ZERO-AUTH"]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "MEDIUM"
    assert "initialize response carried no tool list" in f["severity_basis"]
    assert f["response_status"] == 200
    assert f["request_body"]
    assert f["response_body"]
