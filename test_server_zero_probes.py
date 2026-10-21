#!/usr/bin/env python3
"""Test server: passes preflight, serves valid discovery, all probes NOT_OBSERVED.
For testing EXIT 5 (zero probes measured / all NOT_OBSERVED)."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class ZeroProbesHandler(BaseHTTPRequestHandler):
    """OAuth server that passes discovery but has no probe endpoints."""

    def do_GET(self):
        # /resource_metadata - Protected Resource Metadata (RFC 9728)
        # Contains: resource identifier, issuer, list of authorization servers
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:8000/mcp",  # RFC 9728: required field in PRM
                "issuer": "http://127.0.0.1:8000",
                "authorization_servers": ["http://127.0.0.1:8000"]
            }).encode())
        # /.well-known/oauth-authorization-server - OAuth Authorization Server Metadata (RFC 8414)
        # Does NOT contain resource or issuer (issuer goes in the PRM)
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
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
        else:
            # All probe endpoints return 404 (NOT_OBSERVED)
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        # MCP endpoints require OAuth (401 with WWW-Authenticate header)
        if self.path == "/initialize" or self.path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:8000/resource_metadata"')
            self.end_headers()
        else:
            # All other endpoints return 404
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = HTTPServer(("127.0.0.1", port), ZeroProbesHandler)
    server.serve_forever()
