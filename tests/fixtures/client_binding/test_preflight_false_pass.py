"""Fixture: probe_mcp_preflight must return FAIL/HIGH on unauthenticated initialize."""
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
    """Server that returns 200 JSON-RPC initialize without auth."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path == "/mcp":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"jsonrpc": "2.0", "result": {}}
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
from mcp_authscan.resource_probes import probe_mcp_preflight

result = probe_mcp_preflight(f"http://127.0.0.1:{port}/mcp")

print("Status: %s" % result.status)
print("Severity: %s" % result.severity)
print("Detail: %s" % result.detail)
print("Expected: status=FAIL, severity=HIGH (unauthenticated JSON-RPC initialize)")
