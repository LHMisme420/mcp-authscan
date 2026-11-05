import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _resource_metadata_url(self):
        return self.server.base_url + "/.well-known/oauth-protected-resource"

    def _unauthorized_mcp(self):
        body = b'{"error": "unauthorized"}'
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "WWW-Authenticate",
            'Bearer resource_metadata="%s"' % self._resource_metadata_url(),
        )
        self.end_headers()
        self.wfile.write(body)
        return None

    def do_GET(self):
        self.server.touches.append(self.path)
        base = self.server.base_url
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            # Advertise the decoy's OWN base URL as the authorization server.
            # A placeholder (e.g. https://decoy.invalid) is unreachable, so the
            # client's discovery dies before the token request and the issuer
            # binding is never exercised.
            return self.reply(200, {
                "resource": base + "/mcp",
                "authorization_servers": [base],
            })
        if self.path.startswith("/.well-known/oauth-authorization-server"):
            return self.reply(200, {
                "issuer": base,
                "token_endpoint": base + "/token",
                "authorization_endpoint": base + "/authorize",
                "registration_endpoint": base + "/register",
                # Required by RFC 8414; the TypeScript SDK validates the
                # document strictly (the Python/fastmcp clients do not), and
                # omitting these stops its flow before the token request.
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "client_credentials"],
            })
        if self.path.startswith("/mcp"):
            return self._unauthorized_mcp()
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        self.server.touches.append("POST " + self.path)
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
            return self._unauthorized_mcp()
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
    server.touches = []
    server.base_url = "http://127.0.0.1:%d" % server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def stop_decoy(server):
    server.shutdown()
    server.server_close()
