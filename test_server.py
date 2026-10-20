#!/usr/bin/env python3
"""Reference MCP server with known vulnerabilities for testing mcp-authscan."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class ReferenceOAuthHandler(BaseHTTPRequestHandler):
    """Intentionally vulnerable OAuth server for scanner testing."""

    def do_GET(self):
        # /sse and /tools/list exist and accept unauthenticated requests (D1 vulnerability)
        if self.path == "/sse" or self.path == "/tools/list":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "service": "oauth-server",
                "tools": ["list_resources", "call_tool", "read_resource"]
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # /message and /mcp exist and accept unauthenticated requests (D1 vulnerability)
        # Also accept invalid tokens (D3 vulnerability)
        if self.path == "/message" or self.path == "/mcp":
            # Both vulnerabilities: no auth check, no token validation
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len) if content_len > 0 else b''

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            try:
                data = json.loads(body)
                response = {
                    "status": "success",
                    "method": data.get("method", "unknown"),
                    "result": {}
                }
            except:
                response = {"status": "success", "result": {}}

            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logs

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = HTTPServer(("127.0.0.1", port), ReferenceOAuthHandler)
    print(f"[*] Reference vulnerable server on http://127.0.0.1:{port}")
    print(f"[*] Vulnerable endpoints: /sse, /message, /mcp, /tools/list (no auth required)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
