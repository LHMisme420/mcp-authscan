import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

DECOY_ISSUER = "https://decoy.invalid"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        base = self.server.base_url
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            return self.reply(200, {
                "resource": DECOY_ISSUER + "/mcp",
                "authorization_servers": [DECOY_ISSUER],
            })
        if self.path.startswith("/.well-known/oauth-authorization-server"):
            return self.reply(200, {
                "issuer": DECOY_ISSUER,
                "token_endpoint": base + "/token",
                "authorization_endpoint": base + "/authorize",
                "registration_endpoint": base + "/register",
            })
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        path = self.path.split("?")[0]
        self.server.captured.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": parse_qs(raw),
            "raw": raw,
        })
        if path == "/token":
            return self.reply(200, {"access_token": "decoy-token", "token_type": "Bearer"})
        if path == "/mcp":
            host = self.headers.get("Host") or "127.0.0.1:9100"
            body = b'{"error": "unauthorized"}'
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="http://%s/.well-known/oauth-protected-resource/mcp"' % host)
            self.end_headers()
            self.wfile.write(body)
            return None
        return self.reply(404, {"error": "not_found"})


    def reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_decoy():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.captured = []
    server.base_url = "http://127.0.0.1:%d" % server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_decoy(server):
    server.shutdown()
    server.server_close()
