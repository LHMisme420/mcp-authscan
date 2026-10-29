"""Exit code proof: scanner verdict → exit code mapping."""
import json
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class ExitCodeTests(unittest.TestCase):
    """Proof that scanner exit codes work as designed."""

    @staticmethod
    def _start_server(port, response_code, body=b''):
        """Start a loopback fixture server."""
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.send_response(response_code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        time.sleep(0.1)
        return server

    def test_exit_3_private_ip_rebinding_protection(self):
        """Exit 3: private IP triggers DNS rebinding protection."""
        server = self._start_server(9003, 401)
        result = subprocess.run(["mcp-authscan", "http://127.0.0.1:9003", "--authorized-by", "Test", "--auth-basis", "Test", "--contact", "test@test.com"], capture_output=True)
        self.assertEqual(result.returncode, 3)
        server.shutdown()

    def test_exit_3_unreachable_target(self):
        """Exit 3: network unreachable."""
        result = subprocess.run(["mcp-authscan", "http://127.0.0.1:9999", "--authorized-by", "Test", "--auth-basis", "Test", "--contact", "test@test.com"], capture_output=True)
        self.assertEqual(result.returncode, 3)

    def test_exit_3_refused_when_target_neither_url_nor_readable_source(self):
        """Exit 3, no report: target is neither an http(s) URL nor a readable source directory."""
        # User types 'app.example.com/mcp' instead of 'https://app.example.com/mcp'.
        # A schemeless target is treated as a local path; with nothing readable there,
        # nothing is examined, so the scan is refused rather than reported.
        # Contract: nothing to examine -> exit 3, no report (no text, JSON, or hash on stdout).
        result = subprocess.run(
            [sys.executable, "-m", "mcp_authscan.cli_wrapper",
             "nonexistent-dir-that-does-not-exist",
             "--json",
             "--authorized-by", "Test",
             "--auth-basis", "test",
             "--contact", "test@example.com"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 3,
            f"Expected exit 3 (refused, nothing examined), got {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}")
        self.assertEqual(result.stdout, "",
            "Expected no report on stdout for a refused scan")


    def test_exit_6_usage_error(self):
        """Exit 6: usage error (missing required argument)."""
        result = subprocess.run(
            [sys.executable, "-m", "mcp_authscan.cli_wrapper"],
            capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 6,
            f"Expected exit 6 for usage error, got {result.returncode}")


if __name__ == "__main__":
    unittest.main()
