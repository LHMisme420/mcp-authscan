import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

TOKENS = {"tok-a": "a", "tok-b": "b"}
RECORDS = {"r-a": {"id": "r-a", "owner": "a"}, "r-b": {"id": "r-b", "owner": "b"}}
MISBEHAVE = os.environ.get("MISBEHAVE") == "1"

class H(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        token = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
        tenant = TOKENS.get(token)
        length = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            body = {}
        if tenant is None:
            return self.reply(401, {"error": "unauthorized"})
        args = (body.get("params") or {}).get("arguments") or {}
        record = RECORDS.get(args.get("id"))
        if record is None:
            return self.reply(404, {"error": "no such record"})
        if record["owner"] != tenant and not MISBEHAVE:
            return self.reply(403, {"error": "forbidden"})
        return self.reply(200, {"jsonrpc": "2.0", "id": body.get("id"), "result": record})

    def reply(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(os.environ.get("PORT", "8770"))), H).serve_forever()
