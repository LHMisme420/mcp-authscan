import json, os, subprocess, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import pytest
pytestmark = pytest.mark.timeout(30)
RUN = os.path.join(os.path.dirname(__file__), "_run_monolith.py")
def _server(body):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 10
        def _reply(self):
            n = int(self.headers.get("Content-Length") or 0)
            if n: self.rfile.read(n)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            try: self.wfile.write(body); self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError): pass
            self.close_connection = True
        do_POST = do_GET = _reply
        def log_message(self, *a): pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
def _scan(tmp_path, body):
    srv = _server(body)
    url = "http://127.0.0.1:%d/mcp" % srv.server_address[1]
    out = tmp_path / "r.json"
    argv = [url, "--allow-private", "--json", "--output", str(out),
            "--contact", "t@example.com", "--authorized-by", "T",
            "--auth-basis", "local fixture", "--scope", "fixture"]
    try:
        try:
            proc = subprocess.run([sys.executable, RUN] + argv,
                                  capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired as e:
            raise AssertionError("hang >30s: %r" % ((e.stderr or b"")[:400],))
        assert out.exists(), "no report; rc=%s err=%s" % (proc.returncode, proc.stderr[:400])
        data = json.loads(out.read_text())
    finally:
        srv.shutdown(); srv.server_close()
    hits = [f for f in data["findings"] if f["rule"] == "ZERO-AUTH"]
    assert len(hits) == 1, data.get("findings")
    return hits[0], data
def test_calib_write_tool_is_critical(tmp_path):
    body = json.dumps({"result": {"tools": [{"name": "delete_record"}]}}).encode()
    f, data = _scan(tmp_path, body)
    assert f["severity"] == "CRITICAL"
    assert "delete" in f["severity_basis"]
    assert data["severity_calibration_version"] == "2026.11.05.1"
def test_calib_read_only_tools_are_high(tmp_path):
    body = json.dumps({"result": {"tools": [{"name": "list_items"}, {"name": "get_status"}]}}).encode()
    f, _ = _scan(tmp_path, body)
    assert f["severity"] == "HIGH"
    assert "none with a write" in f["severity_basis"]
def test_calib_no_tools_is_medium(tmp_path):
    body = json.dumps({"result": {"serverInfo": {"name": "x"}}}).encode()
    f, _ = _scan(tmp_path, body)
    assert f["severity"] == "MEDIUM"
    assert "demonstrated no tools" in f["severity_basis"]
def test_calib_unparseable_is_medium():
    # Preflight screens a non-JSON (HTML) body out as not-MCP before grading, so this
    # branch cannot be reached through a full scan (that screening is what stops the
    # SPA-HTML false positives). Test the grader's unparseable branch directly.
    from mcp_authscan.monolith import grade_zero_auth
    sev, basis = grade_zero_auth("<html>not json</html>")
    assert sev == "MEDIUM"
    assert "did not parse" in basis
