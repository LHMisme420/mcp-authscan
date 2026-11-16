import sys,threading,subprocess
from http.server import BaseHTTPRequestHandler as B, ThreadingHTTPServer as T
def lm(*a): pass
def dp(self):
    n=int(self.headers.get('Content-Length') or 0)
    self.rfile.read(n)
    self.send_response(302)
    self.send_header('Location','http://elsewhere.example/mcp')
    self.send_header('Content-Length','0')
    self.end_headers()
def gp(self):
    self.send_response(405)
    self.send_header('Content-Length','0')
    self.end_headers()
H=type('H',(B,),{})
setattr(H,'do'+chr(95)+'POST',dp)
setattr(H,'do'+chr(95)+'GET',gp)
setattr(H,'log'+chr(95)+'message',lm)
s=T(('127.0.0.1',0),H)
threading.Thread(target=s.serve_forever,daemon=True).start()
h='127.0.0.1:%d'%s.server_address[1]
c=[sys.executable,'-m','mcp_authscan.monolith','http://'+h+'/mcp','--contact','b@example.invalid','--authorized-by','bench','--auth-basis','x','--allow-private','--allow-host',h]
p=subprocess.run(c,cwd='/home/lhmisme/mcp-authscan',capture_output=True,text=True,timeout=120)
o=p.stdout+p.stderr
s.shutdown()
print('exit',p.returncode,'want 6','MATCH' if p.returncode==6 else 'DIVERGENCE')
print('hop named','MATCH' if 'redirect refused' in o.lower() and 'elsewhere.example' in o else 'DIVERGENCE')
print('not graded as non-MCP','MATCH' if 'NOT AN MCP SERVER' not in o.upper() else 'DIVERGENCE')
for l in o.splitlines()[-8:]: print(l)
