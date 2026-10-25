#!/usr/bin/env python3
import http.server
import socketserver
import os

PORT = 3000

class CORSRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        super().end_headers()

os.chdir('dashboard')
with socketserver.TCPServer(("", PORT), CORSRequestHandler) as httpd:
    print(f"✅ Dashboard running at http://127.0.0.1:{PORT}")
    httpd.serve_forever()
