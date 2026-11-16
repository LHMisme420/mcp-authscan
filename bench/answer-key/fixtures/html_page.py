import sys
from http.server import BaseHTTPRequestHandler,HTTPServer
P=int(sys.argv[1])
B=b'<html><body>hello</body></html>'
class H(BaseHTTPRequestHandler):
    def go(s):
        s.send_response(200)
        s.send_header('Content-Type','text/html')
        s.send_header('Content-Length',str(len(B)))
        s.end_headers()
        s.wfile.write(B)
    def do_GET(s):
        s.go()
    def do_POST(s):
        s.rfile.read(int(s.headers.get('Content-Length',0)))
        s.go()
    def do_HEAD(s):
        s.go()
    def log_message(s,*a):
        pass
HTTPServer(('127.0.0.1',P),H).serve_forever()
