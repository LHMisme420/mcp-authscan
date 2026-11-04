import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class DerivedMetadataHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        host = self.headers.get("Host", "")
        if path == "/.well-known/oauth-protected-resource":
            self._json(200, {
                "resource": "http://" + host + "/mcp",
                "authorization_servers": ["http://" + host],
                "bearer_methods_supported": ["header"],
            })
            return
        if path == "/.well-known/oauth-authorization-server":
            self._json(200, {
                "issuer": "http://" + host,
                "authorization_endpoint": "http://" + host + "/authorize",
                "token_endpoint": "http://" + host + "/token",
            })
            return
        self._json(404, {"error": "not_found"})

    def do_POST(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer realm=mcp")
        self.send_header("Access-Control-Allow-Origin", "http://localhost")
        self.send_header("Content-Length", "0")
        self.end_headers()


def start():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DerivedMetadataHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, server.server_address[1]
