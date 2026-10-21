#!/usr/bin/env python3
"""Non-MCP server: responds but no OAuth/MCP endpoints."""
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class NotMCPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/initialize" or self.path == "/mcp":
            # Returns 200 OK instead of 401 with OAuth challenge
            self.send_response(200)
            self.send_header("Content-type", "text/plain")
            self.end_headers()
            self.wfile.write(b"This is not an MCP server")
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        pass

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9003
    HTTPServer(("127.0.0.1", port), NotMCPHandler).serve_forever()
