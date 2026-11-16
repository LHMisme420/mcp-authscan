import sys,os,json,threading,subprocess
from http.server import BaseHTTPRequestHandler as B, ThreadingHTTPServer as T
REPO='/home/lhmisme/mcp-authscan'
def lm(*a): pass
def rp(self):
    n=int(self.headers.get('Content-Length') or 0)
    raw=self.rfile.read(n)
    d=json.loads(raw or b'{}')
    m=d.get('method') or ''
    i=d.get('id',1)
    if m=='initialize':
        out={'jsonrpc':'2.0','id':i,'result':{'protocolVersion':'2025-06-18','capabilities':{'tools':{}},'serverInfo':{'name':'adv','version':'0'}}}
    elif m=='tools/list':
        out={'jsonrpc':'2.0','id':i,'result':{'tools':[{'name':'list_items','description':'List items','inputSchema':{'type':'object'}}]}}
    elif m=='tools/call':
        out={'jsonrpc':'2.0','id':i,'error':{'code':-32602,'message':'Invalid params'}}
    else:
        out={'jsonrpc':'2.0','id':i,'result':{}}
    b=json.dumps(out).encode()
    self.send_response(200)
    self.send_header('Content-Type','application/json')
    self.send_header('Content-Length',str(len(b)))
    self.end_headers()
    self.wfile.write(b)
def gp(self):
    self.send_response(405)
    self.send_header('Content-Length','0')
    self.end_headers()
H=type('H',(B,),{})
setattr(H,'do'+chr(95)+'POST',rp)
setattr(H,'do'+chr(95)+'GET',gp)
setattr(H,'log'+chr(95)+'message',lm)
s=T(('127.0.0.1',0),H)
host='127.0.0.1:%d'%s.server_address[1]
threading.Thread(target=s.serve_forever,daemon=True).start()
cmd=[sys.executable,'-m','mcp_authscan.monolith','http://'+host+'/mcp','--contact','bench@example.invalid','--authorized-by','bench','--auth-basis','self declared','--allow-private','--allow-host',host]
p=subprocess.run(cmd,cwd=REPO,capture_output=True,text=True,timeout=120)
out=p.stdout+p.stderr
print('EXIT',p.returncode)
print('ZERO-AUTH', 'ZERO-AUTH' in out.upper())
print('REFUSED', 'REFUSED' in out.upper())
for l in out.splitlines()[-14:]: print(l)
s.shutdown()
