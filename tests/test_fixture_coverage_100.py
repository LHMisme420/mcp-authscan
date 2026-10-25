#!/usr/bin/env python3
"""Test server: 100% coverage (7/7 verdicts). Probes 7-8 excluded (need authorization flow); probes 1-6,9 reach verdicts."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class CompleteHandler(BaseHTTPRequestHandler):
    """Minimal complete OAuth server - all endpoints working."""

    def do_GET(self):
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:9000/mcp",
                "authorization_servers": ["http://127.0.0.1:9000"]
            }).encode())
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "issuer": "http://127.0.0.1:9000",
                "token_endpoint": "http://127.0.0.1:9000/token",
                "authorization_endpoint": "http://127.0.0.1:9000/authorize",
                "registration_endpoint": "http://127.0.0.1:9000/register",
                "revocation_endpoint": "http://127.0.0.1:9000/revoke",
                "device_authorization_endpoint": "http://127.0.0.1:9000/device",
                "jwks_uri": "http://127.0.0.1:9000/jwks",
                "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": ["authorization_code"],
                "response_types_supported": ["code"]
            }).encode())
        elif self.path == "/jwks":
            # Valid JWKS response with Cache-Control
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "keys": [{"kty": "RSA", "use": "sig", "alg": "RS256"}]
            }).encode())
        elif self.path == "/token":
            # Token endpoint: return invalid_client for probe 9 (client-auth) to PASS
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("WWW-Authenticate", 'Bearer realm="mcp"')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
        elif self.path == "/authorize":
            # Authorization endpoint: not testing here, but return something sensible
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized"}).encode())
        elif self.path in ["/register", "/revoke", "/device"]:
            # Other endpoints: return invalid_client as fallback
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/initialize" or self.path == "/mcp":
            # Preflight: 401 with OAuth challenge
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:9000/resource_metadata"')
            self.end_headers()
        elif self.path == "/token":
            # Token endpoint POST: return unsupported_grant_type for probe 6 (password-grant), invalid_client for probe 9 (client-auth)

            # Read request body to determine which probe is calling
            content_len = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_len).decode() if content_len > 0 else ""

            # Probe 6 (password-grant) sends grant_type=password
            if "grant_type=password" in body:
                # Unsupported grant type: 400 Bad Request (not 401 Unauthorized)
                self.send_response(400)
                self.send_header("Content-type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "unsupported_grant_type"}).encode())
            else:
                # Probe 9 (client-auth) or other requests get invalid_client: 401 Unauthorized
                self.send_response(401)
                self.send_header("Content-type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("WWW-Authenticate", 'Bearer realm="mcp"')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
        elif self.path == "/authorize":
            # Authorization endpoint: return something
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unauthorized"}).encode())
        elif self.path in ["/register", "/revoke", "/device"]:
            # Other endpoints
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_client"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    server = HTTPServer(("127.0.0.1", port), CompleteHandler)
    server.serve_forever()
