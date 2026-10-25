#!/usr/bin/env python3
"""Test server: all in-scope probes reach PASS verdict."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class PassingHandler(BaseHTTPRequestHandler):
    """OAuth server where all testable probes reach PASS."""

    def do_GET(self):
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:4000/mcp",
                "authorization_servers": ["http://127.0.0.1:4000"]
            }).encode())
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "issuer": "http://127.0.0.1:4000",
                "token_endpoint": "http://127.0.0.1:4000/token",
                "authorization_endpoint": "http://127.0.0.1:4000/authorize",
                "registration_endpoint": "http://127.0.0.1:4000/register",
                "revocation_endpoint": "http://127.0.0.1:4000/revoke",
                "device_authorization_endpoint": "http://127.0.0.1:4000/device",
                "jwks_uri": "http://127.0.0.1:4000/jwks",
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
                "keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "key1"}]
            }).encode())
        elif self.path in ["/token", "/authorize", "/register", "/revoke", "/device"]:
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("WWW-Authenticate", 'Bearer realm="mcp"')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/initialize" or self.path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:4000/resource_metadata"')
            self.end_headers()
        elif self.path in ["/token", "/authorize", "/register", "/revoke", "/device"]:
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("WWW-Authenticate", 'Bearer realm="mcp"')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
    server = HTTPServer(("127.0.0.1", port), PassingHandler)
    server.serve_forever()
