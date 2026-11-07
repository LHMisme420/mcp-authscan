import json
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1] if len(sys.argv) > 1 else "enforcing"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9201
ISSUED = set()
RES = [{"uri": "file:///fixture/note.txt", "name": "note", "mimeType": "text/plain"}]


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, code, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        msg = json.loads(self.rfile.read(n) or b"{}")
        mid, m = msg.get("id"), msg.get("method")
        sid = self.headers.get("Mcp-Session-Id")
    def _send(self, code, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        msg = json.loads(self.rfile.read(n) or b"{}")
        mid, m = msg.get("id"), msg.get("method")
        sid = self.headers.get("Mcp-Session-Id")
        if mid is None:
            self.send_response(202)
            self.end_headers()
            return
        if m == "initialize":
            new = str(uuid.uuid4())
            ISSUED.add(new)
            self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "resources-fixture", "version": "1.0"}}},
                {"Mcp-Session-Id": new})
        elif m == "resources/list":
            self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {"resources": RES}})
        elif m == "resources/read":
            if MODE == "enforcing" and sid not in ISSUED:
                self._send(403, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32001, "message": "unknown session"}})
                return
            uri = (msg.get("params") or {}).get("uri")
            self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {"contents": [
                {"uri": uri, "mimeType": "text/plain", "text": "fixture resource"}]}})
        else:
            self._send(404, {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}})


def main():
    print("resources fixture %s on 127.0.0.1:%d" % (MODE, PORT), flush=True)
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()


if sys.argv[0].endswith("resources_fixture.py"):
    main()
