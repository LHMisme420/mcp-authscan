#!/usr/bin/env python3
"""Minimal MCP test server for security scanning."""
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys

class MCPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests for MCP discovery and probes."""
        if self.path == '/.well-known/mcp.json' or self.path == '/mcp.json':
            # MCP discovery endpoint
            response = {
                "mcpVersion": "2024-11",
                "protocolVersion": "1.0",
                "name": "test-mcp",
                "version": "0.1.0",
                "capabilities": {
                    "resources": {},
                    "tools": {},
                    "sampling": {}
                }
            }
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/sse':
            # SSE endpoint for testing
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def log_message(self, format, *args):
        """Suppress request logging."""
        pass

if __name__ == '__main__':
    host = '127.0.0.1'
    port = 8765
    server = HTTPServer((host, port), MCPHandler)
    print(f"MCP test server running on http://{host}:{port}")
    sys.stdout.flush()
    server.serve_forever()
