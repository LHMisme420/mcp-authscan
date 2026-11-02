import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer


class HaltedHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer realm=demo")
        self.end_headers()

    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_halted_scan_does_not_exit_zero(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), HaltedHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = "http://127.0.0.1:%d/mcp" % port
    out = tmp_path / "halted.txt"
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "mcp_authscan", target,
             "--allow-private", "--allow-host", "127.0.0.1",
             "--authorized-by", "test fixture",
             "--auth-basis", "loopback fixture owned by this test",
             "--contact", "test@example.com",
             "--output", str(out)],
            capture_output=True, text=True, timeout=90)
    finally:
        srv.shutdown()
    assert "INCOMPLETE" in proc.stdout.upper(), proc.stdout[-1500:]
    assert proc.returncode == 5, (proc.returncode, proc.stderr[-600:])
