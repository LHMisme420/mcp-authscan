#!/usr/bin/env python3
"""Reference MCP server with known vulnerabilities for testing mcp-authscan."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class ReferenceOAuthHandler(BaseHTTPRequestHandler):
    """Intentionally vulnerable OAuth server for scanner testing."""

    def do_GET(self):
        # /resource_metadata - provides authorization server URLs (RFC 9728)
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            # Missing 'resource' field - this is a FAIL on resource-binding check (HIGH)
            self.wfile.write(json.dumps({
                "authorization_servers": ["http://127.0.0.1:8000"]
            }).encode())
        # /.well-known/oauth-authorization-server - OAuth server metadata (RFC 8414)
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "issuer": "http://127.0.0.1:8000",
                "token_endpoint": "http://127.0.0.1:8000/token",
                "authorization_endpoint": "http://127.0.0.1:8000/authorize",
                "registration_endpoint": "http://127.0.0.1:8000/register",
                "revocation_endpoint": "http://127.0.0.1:8000/revoke",
                "device_authorization_endpoint": "http://127.0.0.1:8000/device",
                "jwks_uri": "http://127.0.0.1:8000/jwks",
                "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code"],
                "response_types_supported": ["code"]
            }).encode())
        # /sse and /tools/list exist and accept unauthenticated requests (D1 vulnerability)
        elif self.path == "/sse" or self.path == "/tools/list":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "ok",
                "service": "oauth-server",
                "tools": ["list_resources", "call_tool", "read_resource"]
            }).encode())
        # OAuth probe endpoints - return valid responses for testability
        elif self.path == "/jwks":
            # JWKS endpoint - return valid JWKS response
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "public, max-age=3600")  # For cache-control test
            self.end_headers()
            self.wfile.write(json.dumps({"keys": []}).encode())
        elif self.path in ["/token", "/authorize", "/register", "/revoke", "/device"]:
            # OAuth endpoints - return 401/403 (invalid request, can be tested)
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        import time
        time.sleep(1)  # Force different elapsed times between scan runs
        # MCP endpoints require OAuth (401 with WWW-Authenticate header)
        if self.path == "/initialize" or self.path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:8000/resource_metadata"')
            self.end_headers()
        # /message exists and accepts unauthenticated requests (D1 vulnerability)
        # Also accepts invalid tokens (D3 vulnerability)
        elif self.path == "/message":
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
        # OAuth probe endpoints - return 401/403 for testability
        elif self.path in ["/token", "/authorize", "/register", "/revoke", "/device"]:
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
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
