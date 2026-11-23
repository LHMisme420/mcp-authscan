import sys
from http.server import BaseHTTPRequestHandler,HTTPServer
P=int(sys.argv[1])
class H(BaseHTTPRequestHandler):
    def do_POST(s):
        s.rfile.read(int(s.headers.get('Content-Length',0)))
        s.send_response(401); s.end_headers()
    def do_GET(s):
        s.send_response(401); s.end_headers()
    def log_message(s,*a): pass
HTTPServer(('127.0.0.1',P),H).serve_forever()
