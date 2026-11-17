import json,sys
from http.server import BaseHTTPRequestHandler,HTTPServer
PORT=int(sys.argv[1])
class H(BaseHTTPRequestHandler):
    def log_message(self,*a):
        pass
    def do_POST(self):
        n=int(self.headers.get("Content-Length") or 0)
        try:
            body=json.loads(self.rfile.read(n).decode("utf-8","replace") or "{}")
        except ValueError:
            body={}
        mid=body.get("id")
        out={"jsonrpc":"2.0","id":mid,"error":{"code":-32001,"message":"Unauthorized: a client credential is required for this server"}}
        raw=json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        self.send_response(405)
        self.send_header("Content-Length","0")
        self.end_headers()
HTTPServer(("127.0.0.1",PORT),H).serve_forever()
