#!/usr/bin/env python3
"""Reproduction test: token-cors should FAIL when ACAO: * is present."""
import sys
import time
import threading
import json

sys.path.insert(0, '/home/claude/lhmisme420/mcp-authscan')

import mcp_authscan.monolith as monolith_module
monolith_module.ALLOW_PRIVATE_TARGETS = True

from mcp_authscan.monolith import scan_live_server
from http.server import HTTPServer, BaseHTTPRequestHandler

class WildcardCORSFixture(BaseHTTPRequestHandler):
    """Fixture that returns wildcard ACAO on token endpoint."""
    def do_GET(self):
        if self.path == "/resource_metadata":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "resource": "http://127.0.0.1:9999/mcp",
                "authorization_servers": ["http://127.0.0.1:9999"]
            }).encode())
        elif self.path == "/.well-known/oauth-authorization-server":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "issuer": "http://127.0.0.1:9999",
                "token_endpoint": "http://127.0.0.1:9999/token",
                "authorization_endpoint": "http://127.0.0.1:9999/authorize",
                "jwks_uri": "http://127.0.0.1:9999/jwks"
            }).encode())
        elif self.path == "/jwks":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"keys": [{"kty": "EC"}]}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path in ["/initialize", "/mcp"]:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:9999/resource_metadata"')
            self.end_headers()
        elif self.path == "/token":
            # THIS IS THE TEST: return wildcard ACAO with error response
            self.send_response(400)
            self.send_header("Content-type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "authorization, content-type")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "unsupported_grant_type"}).encode())
        elif self.path == "/authorize":
            self.send_response(401)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "invalid_request"}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass

def start_fixture():
    """Start fixture on port 9999."""
    def run():
        HTTPServer(("127.0.0.1", 9999), WildcardCORSFixture).serve_forever()
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    time.sleep(0.5)

if __name__ == "__main__":
    print("=" * 70)
    print("REPRODUCTION TEST: token-cors with wildcard ACAO should FAIL")
    print("=" * 70)

    start_fixture()

    print("\nScanning http://127.0.0.1:9999/mcp...")
    try:
        F, server_reachable, probe_status, discovery_info, (oauth_records, probe_results) = scan_live_server("http://127.0.0.1:9999/mcp")

        print(f"\nProbe results: {probe_status}")

        # Find probe 4 (token-cors) in oauth_records
        probe_4 = None
        for probe in oauth_records:
            if probe.probe_id == 4:
                probe_4 = probe
                break

        if not probe_4:
            print("ERROR: Probe 4 not found!")
            print(f"DEBUG: oauth_records: {oauth_records}")
            sys.exit(1)

        print(f"\nProbe 4 (token-cors):")
        print(f"  Status: {probe_4.status}")
        print(f"  Detail: {probe_4.detail}")
        print(f"  Evidence: {getattr(probe_4, 'evidence', 'N/A')}")

        # ASSERTION: Probe 4 should FAIL when ACAO: * is present
        if probe_4.status == "FAIL":
            print("\n✓ PASS: Probe 4 correctly returned FAIL for wildcard ACAO")
            sys.exit(0)
        else:
            print(f"\n✗ FAIL: Probe 4 returned {probe_4.status} instead of FAIL")
            print("This is the bug: headers show wildcard ACAO but probe says PASS")
            sys.exit(1)

    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
