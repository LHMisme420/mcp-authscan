#!/usr/bin/env python3
"""Test server with security findings: accepts password grant (FAIL). Complete coverage for EXIT 1."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class FindingsHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:9002/mcp",
                "authorization_servers": ["http://127.0.0.1:9002"]
            }).encode())
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "issuer": "http://127.0.0.1:9002",
                "token_endpoint": "http://127.0.0.1:9002/token",
                "authorization_endpoint": "http://127.0.0.1:9002/authorize",
                "registration_endpoint": "http://127.0.0.1:9002/register",
                "revocation_endpoint": "http://127.0.0.1:9002/revoke",
                "device_authorization_endpoint": "http://127.0.0.1:9002/device",
                "jwks_uri": "http://127.0.0.1:9002/jwks",
                "code_challenge_methods_supported": ["S256"]
            }).encode())
        elif self.path == "/jwks":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": [{"kty": "RSA"}]}).encode())
        elif self.path in ["/authorize", "/register", "/revoke", "/device"]:
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path in ["/initialize", "/mcp"]:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:9002/resource_metadata"')
            self.end_headers()
        elif self.path == "/token":
            # VULNERABLE: accept password grant (should reject) - causes HIGH severity FAIL
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"access_token": "fake_token"}).encode())
        elif self.path in ["/authorize", "/register", "/revoke", "/device"]:
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9002
    HTTPServer(("127.0.0.1", port), FindingsHandler).serve_forever()
