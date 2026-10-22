"""Exit code proof: scanner verdict → exit code mapping."""
import unittest
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

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

if __name__ == "__main__":
    unittest.main()
