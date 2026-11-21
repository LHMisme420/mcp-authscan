import json,sys
from http.server import BaseHTTPRequestHandler,HTTPServer
P=int(sys.argv[1])
I='http://127.0.0.1:%d'%P
PR=json.dumps({'resource':I+'/mcp','authorization_servers':[I]}).encode()
AS=json.dumps({'issuer':I,'authorization_endpoint':I+'/authorize','token_endpoint':I+'/token','jwks_uri':I+'/jwks','response_types_supported':['code'],'grant_types_supported':['authorization_code'],'code_challenge_methods_supported':['S256'],'token_endpoint_auth_methods_supported':['client_secret_basic']}).encode()
JW=open('bench/answer-key/jwks.json','rb').read()
W='Bearer resource_metadata="'+I+'/.well-known/oauth-protected-resource/mcp"'
TOOLS=[{'name':'list_items','description':'List items.','inputSchema':{'type':'object','properties':{}}}]
INIT={'jsonrpc':'2.0','result':{'protocolVersion':'2025-06-18','serverInfo':{'name':'discovery-open','version':'1'},'capabilities':{'tools':{}}}}
TL={'jsonrpc':'2.0','result':{'tools':TOOLS}}
class H(BaseHTTPRequestHandler):
    def put(s,b,c=200):
        s.send_response(c)
        s.send_header('Content-Type','application/json'); s.send_header('Cache-Control','no-store')
        s.send_header('Content-Length',str(len(b)))
        s.end_headers()
        s.wfile.write(b)
    def do_GET(s):
        p=s.path
        if p.startswith('/.well-known/oauth-protected-resource'):
            return s.put(PR)
        if p.startswith('/.well-known/oauth-authorization-server'):
            return s.put(AS)
        if p=='/jwks':
            return s.put(JW)
        s.send_response(401)
        s.send_header('WWW-Authenticate',W)
        s.send_header('Content-Length','0')
        s.end_headers()
    def do_POST(s):
        raw=s.rfile.read(int(s.headers.get('Content-Length',0)))
        if s.path!='/mcp':
         return s.put(b'{"error":"invalid_client"}',401)
        try:
         req=json.loads(raw or b'{}')
        except Exception:
         req={}
        m=req.get('method'); i=req.get('id')
        if m=='initialize':
         d=dict(INIT); d['id']=i
         return s.put(json.dumps(d).encode())
        if m=='tools/list':
         d=dict(TL); d['id']=i
         return s.put(json.dumps(d).encode())
        d={'jsonrpc':'2.0','id':i,'error':{'code':-32601,'message':'unknown method'}}
        return s.put(json.dumps(d).encode())
    def log_message(s,*a):
        pass
HTTPServer(('127.0.0.1',P),H).serve_forever()
