#!/usr/bin/env python3
"""Test server: clean complete fixture. Probes 1-6, 9 target verdicts; probes 7-8 (pkce-s256, redirect-uri-exact)
are built and return EXCLUDED without client credentials (prerequisite missing, never sent). Coverage is over the testable probes (9 less EXCLUDED); without a client 7-8 are EXCLUDED today, so the most this fixture can read is 7/7."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
import threading

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

def test_coverage_is_over_the_declared_probe_set(monkeypatch):
    """Testable rule: coverage = (PASS + FAIL) / (in_scope - EXCLUDED), here 9 - 2 = 7.

    The handler names 127.0.0.1:9000 in its metadata, so it is served on 9000.
    No client credentials are configured, so pkce-s256 and redirect-uri-exact are
    EXCLUDED (prerequisite missing, never sent); no probe is NOT_IMPLEMENTED.
    """
    for key in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
        monkeypatch.delenv(key, raising=False)
    import mcp_authscan.monolith as monolith
    from mcp_authscan import oauth_probes_v2
    from mcp_authscan.counts import count_probes, coverage

    # Same flags main() sets for --allow-private and a discovered host.
    monkeypatch.setattr(monolith, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(oauth_probes_v2, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    server = HTTPServer(("127.0.0.1", 9000), CompleteHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        _, _, probe_status, _, (records, _) = monolith.scan_live_server("http://127.0.0.1:9000/mcp")
    finally:
        server.shutdown()
        server.server_close()

    counts = count_probes(records)
    assert counts["in_scope"] == 9
    assert [r.name for r in records if r.status == "NOT_IMPLEMENTED"] == []
    excluded = {r.name: r.limitation for r in records if r.status == "EXCLUDED"}
    assert {"pkce-s256", "redirect-uri-exact"} <= set(excluded)
    assert "client_id" in excluded["pkce-s256"]
    assert excluded["redirect-uri-exact"] == "No registered redirect_uri to compare against"
    assert counts["NOT_IMPLEMENTED"] == 0 and counts["EXCLUDED"] == len(excluded)
    assert counts["attempted"] == counts["PASS"] + counts["FAIL"] + counts["NOT_OBSERVED"]
    assert counts["attempted"] + counts["EXCLUDED"] + counts["NOT_IMPLEMENTED"] == counts["in_scope"]
    assert probe_status["not_implemented"] == 0 and probe_status["excluded"] == len(excluded)
    assert coverage(counts) == (counts["PASS"] + counts["FAIL"]) / (counts["in_scope"] - counts["EXCLUDED"] - counts["NOT_IMPLEMENTED"])
    # The excluded probes leave the denominator: they name their prerequisite instead.
    assert coverage(counts) <= 1.0


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    server = HTTPServer(("127.0.0.1", port), CompleteHandler)
    server.serve_forever()
