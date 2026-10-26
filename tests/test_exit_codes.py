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
        result = subprocess.run([sys.executable, "-m", "mcp_authscan.main", "http://127.0.0.1:9003"], capture_output=True)
        self.assertEqual(result.returncode, 3)
        server.shutdown()

    def test_exit_3_unreachable_target(self):
        """Exit 3: network unreachable."""
        result = subprocess.run([sys.executable, "-m", "mcp_authscan.main", "http://127.0.0.1:9999"], capture_output=True)
        self.assertEqual(result.returncode, 3)

    def test_exit_5_zero_probes_on_no_scheme_typo(self):
        """Exit 5 when URL lacks scheme (typo) → zero probes attempted."""
        # User types 'app.example.com/mcp' instead of 'https://app.example.com/mcp'
        # Scanner falls through to SOURCE_CODE_ASSESSMENT mode, finds nothing.
        # Contract: zero testable probes → exit 5, never 0.
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
        self.assertEqual(result.returncode, 5, 
            f"Expected exit 5 for zero probes, got {result.returncode}.\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}")
        data = json.loads(result.stdout)
        self.assertEqual(data["counts"]["attempted"], 0, 
            "Expected zero probes attempted")


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



    def test_exit_4_not_a_valid_mcp_server(self):
        """Exit 4: target is not a valid MCP server."""
        # Per README: "target is not a valid MCP server"
        # Test with a 200 response that is not MCP (plain text)
        server = self._start_server(9004, 200, b'Hello, this is not an MCP server')
        result = subprocess.run(
            [sys.executable, "-m", "mcp_authscan.cli_wrapper",
             "http://127.0.0.1:9004",
             "--authorized-by", "Test",
             "--auth-basis", "test",
             "--contact", "test@example.com"],
            capture_output=True,
            timeout=10,
        )
        server.shutdown()
        self.assertEqual(result.returncode, 4,
            f"Expected exit 4 for non-MCP server, got {result.returncode}.\n"
            f"stderr: {result.stderr.decode()}")

    def test_exit_6_usage_error(self):
        """Exit 6: usage error (missing required argument)."""
        # Per README: "usage error"
        result = subprocess.run(
            [sys.executable, "-m", "mcp_authscan.cli_wrapper",
             "http://example.com"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 6,
            f"Expected exit 6 for usage error, got {result.returncode}.\n"
            f"stderr: {result.stderr.decode()}")

    def test_exit_4_not_a_valid_mcp_server(self):
        """Exit 4: target is not a valid MCP server."""
        # Per README: "target is not a valid MCP server"
        # Test with a 200 response that is not MCP (plain text)
        server = self._start_server(9004, 200, b'Hello, this is not an MCP server')
        result = subprocess.run(
            [sys.executable, "-m", "mcp_authscan.cli_wrapper",
             "http://127.0.0.1:9004",
             "--authorized-by", "Test",
             "--auth-basis", "test",
             "--contact", "test@example.com"],
            capture_output=True,
            timeout=10,
        )
        server.shutdown()
        self.assertEqual(result.returncode, 4,
            f"Expected exit 4 for non-MCP server, got {result.returncode}.\n"
            f"stderr: {result.stderr.decode()}")

    def test_exit_6_usage_error(self):
        """Exit 6: usage error (missing required argument)."""
        # Per README: "usage error"
        result = subprocess.run(
            [sys.executable, "-m", "mcp_authscan.cli_wrapper",
             "http://example.com"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 6,
            f"Expected exit 6 for usage error, got {result.returncode}.\n"
            f"stderr: {result.stderr.decode()}")
