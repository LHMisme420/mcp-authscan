import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

BODY = json.dumps({
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {"listChanged": True}},
        "serverInfo": {"name": "zeroauth-fixture", "version": "0.0.1"},
        "instructions": "x".ljust(900, "x"),
    }
}).encode()


class _H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

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
    assert proc.returncode == 5, proc.stderr
    data = json.loads(out.read_text())
    assert data["exit_condition"] == "zero_testable_probes"
    assert data["discovery_status"] == "ZERO_AUTH_DETECTED"
    hits = [f for f in data["findings"] if f["rule"] == "ZERO-AUTH"]
    assert len(hits) == 1
    f = hits[0]
    assert f["severity"] == "CRITICAL"
    assert f["response_status"] == 200
    assert f["request_body"]
    assert f["response_body"]
