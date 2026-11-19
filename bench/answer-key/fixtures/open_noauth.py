import json,sys
from http.server import BaseHTTPRequestHandler,HTTPServer
P=int(sys.argv[1])
B=json.dumps(dict(jsonrpc='2.0',id=1,result=dict(protocolVersion='2025-06-18',serverInfo=dict(name='fixture-open',version='1.0'),capabilities=dict(tools=dict(listChanged=True))))).encode()
class H(BaseHTTPRequestHandler):
    def do_POST(s):
        s.rfile.read(int(s.headers.get('Content-Length',0)))
        s.send_response(200)
        s.send_header('Content-Type','application/json')
        s.send_header('Content-Length',str(len(B)))
        s.end_headers()
        s.wfile.write(B)
    def do_GET(s):
        s.send_response(405)
        s.end_headers()
    def log_message(s,*a):
        pass
HTTPServer(('127.0.0.1',P),H).serve_forever()
