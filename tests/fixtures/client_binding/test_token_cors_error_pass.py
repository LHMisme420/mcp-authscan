"""Fixture: probe_token_cors must return EXCLUDED on error responses."""
import json
import http.server
import socketserver
import threading
import time
import sys
import socket

def get_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def run_fixture_server(port):
    """Server that returns 404 for token endpoint."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/token":
                self.send_response(404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"error": "not_found"}
                self.wfile.write(json.dumps(response).encode())
        
        def log_message(self, format, *args):
            pass
    
    try:
        with socketserver.TCPServer(("127.0.0.1", port), Handler) as httpd:
            httpd.timeout = 2
            httpd.handle_request()
    except:
        pass

# Start fixture on available port
port = get_free_port()
thread = threading.Thread(target=run_fixture_server, args=(port,), daemon=True)
thread.start()
time.sleep(0.3)

# Run probe
sys.path.insert(0, '/home/lhmisme/mcp-authscan')
from mcp_authscan.oauth_probes_v2 import probe_token_cors

result = probe_token_cors(f"http://127.0.0.1:{port}/token")

print("Status: %s" % result.status)
print("Severity: %s" % result.severity)
print("Detail: %s" % result.detail)
print("Expected: status=EXCLUDED (cannot assess on 404)")
