#!/usr/bin/env python3
"""Minimal OAuth server fixture for probe testing."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    
    def do_GET(self):
        print(f"[FIXTURE] GET {self.path}", file=sys.stderr)
        if "/mcp" in self.path:
            self.send_response(401)
            self.send_header("www-authenticate", 'Bearer resource_metadata="http://127.0.0.1:8765/.well-known/oauth-protected-resource"')
            self.end_headers()
        elif "oauth-protected-resource" in self.path:
            body = json.dumps({
                "resource": "http://127.0.0.1:8765/mcp",
                "authorization_servers": ["http://127.0.0.1:8765"]
            }).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        elif "oauth-authorization-server" in self.path or ".well-known" in self.path:
            body = json.dumps({
                "issuer": "http://127.0.0.1:8765",
                "token_endpoint": "http://127.0.0.1:8765/token",
                "authorization_endpoint": "http://127.0.0.1:8765/authorize",
                "registration_endpoint": "http://127.0.0.1:8765/register",
                "revocation_endpoint": "http://127.0.0.1:8765/revoke",
                "jwks_uri": "http://127.0.0.1:8765/.well-known/jwks.json"
            }).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        n = int(self.headers.get("content-length", 0))
        self.rfile.read(n)
        if "/mcp" in self.path:
            self.send_response(401)
            self.send_header("www-authenticate", "Bearer resource_metadata=\"http://127.0.0.1:8765/.well-known/oauth-protected-resource\"")
            self.end_headers()
            return
        self.send_response(400)
        self.send_header("cache-control", "no-store")
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"error": "invalid_grant"}')

server = HTTPServer(("127.0.0.1", 8765), Handler)
print("[*] OAuth fixture running on http://127.0.0.1:8765", file=sys.stderr)
server.serve_forever()
