#!/usr/bin/env python3
"""Test server: probes return NOT_OBSERVED due to unexpected errors (not registered client)."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class NotObservedHandler(BaseHTTPRequestHandler):
    """OAuth server where probes reach NOT_OBSERVED (not verdict)."""

    def do_GET(self):
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:7000/mcp",
                "authorization_servers": ["http://127.0.0.1:7000"]
            }).encode())
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
        elif self.path == "/jwks":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "keys": [{"kty": "RSA", "use": "sig", "alg": "RS256"}]
            }).encode())
        elif self.path in ["/token", "/authorize", "/register", "/revoke", "/device"]:
            # Return invalid_request on OAuth endpoints - probes get NOT_OBSERVED
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/initialize" or self.path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:7000/resource_metadata"')
            self.end_headers()
        elif self.path in ["/token", "/authorize", "/register", "/revoke", "/device"]:
            # Return invalid_request - probes get NOT_OBSERVED
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7000
    server = HTTPServer(("127.0.0.1", port), NotObservedHandler)
    server.serve_forever()
