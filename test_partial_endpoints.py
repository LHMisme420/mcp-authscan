#!/usr/bin/env python3
"""Test server: preflight + discovery work, but OAuth endpoints don't exist."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class PartialHandler(BaseHTTPRequestHandler):
    """OAuth server with discovery but no working endpoints."""

    def do_GET(self):
        # /resource_metadata - proper RFC 9728
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:7000/mcp",
                "authorization_servers": ["http://127.0.0.1:7000"]
            }).encode())
        # /.well-known/oauth-authorization-server - proper RFC 8414
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "issuer": "http://127.0.0.1:7000",
                "token_endpoint": "http://127.0.0.1:7000/token",
                "authorization_endpoint": "http://127.0.0.1:7000/authorize",
                "registration_endpoint": "http://127.0.0.1:7000/register",
                "revocation_endpoint": "http://127.0.0.1:7000/revoke",
                "device_authorization_endpoint": "http://127.0.0.1:7000/device",
                "jwks_uri": "http://127.0.0.1:7000/jwks",
                "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code"],
                "response_types_supported": ["code"]
            }).encode())
        else:
            # OAuth endpoints don't exist
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # MCP endpoint requires OAuth (preflight passes)
        if self.path == "/initialize" or self.path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:7000/resource_metadata"')
            self.end_headers()
        else:
            # OAuth endpoints don't exist
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7000
    server = HTTPServer(("127.0.0.1", port), PartialHandler)
    server.serve_forever()
