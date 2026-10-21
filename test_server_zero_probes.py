#!/usr/bin/env python3
"""Test server: passes preflight, serves valid discovery, all probes NOT_OBSERVED.
For testing EXIT 5 (zero probes measured / all NOT_OBSERVED)."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys

class ZeroProbesHandler(BaseHTTPRequestHandler):
    """OAuth server that passes discovery but has no probe endpoints."""

    def do_GET(self):
        # All endpoints 404 - server claims OAuth (401) but has no functional endpoints
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        # MCP endpoint returns 401 (triggers OAuth detection for preflight)
        # but all OAuth endpoints are missing
        if self.path == "/initialize" or self.path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://127.0.0.1:8000/resource_metadata"')
            self.end_headers()
        else:
            # All other endpoints (including OAuth metadata) return 404
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress logging

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = HTTPServer(("127.0.0.1", port), ZeroProbesHandler)
    server.serve_forever()
