import json,sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
T={"read-token":["mcp.read"],"write-token":["mcp.write"]}
N={"notes-read":"mcp.read","notes-write":"mcp.write","leak-write":"mcp.write"}
E={"notes-read":1,"notes-write":1,"leak-write":0}
TOOLS=[{"name":n,"inputSchema":{"type":"object","properties":{}}} for n in N]
class H(BaseHTTPRequestHandler):
 def log_message(self,*a): pass
 def out(self,c,o,h=None):
  b=json.dumps(o).encode()
  self.send_response(c)
  self.send_header("Content-Length",str(len(b)))
  if h: self.send_header("WWW-Authenticate",h)
  self.end_headers()
  self.wfile.write(b)
 def do_POST(self):
  n=int(self.headers.get("Content-Length") or 0)
  q=json.loads(self.rfile.read(n) or b"{}")
  a=self.headers.get("Authorization") or ""
  t=a[7:].strip() if a.startswith("Bearer ") else ""
  Q=chr(34)
  if t not in T: return self.out(401,{"e":"invalid"},"Bearer error="+Q+"invalid"+Q)
  if q.get("method")=="tools/list": return self.out(200,{"r":TOOLS})
  m=(q.get("params") or {}).get("name")
  if m not in N: return self.out(200,{"e":"unknown"})
  if E[m] and N[m] not in T[t]: return self.out(403,{"e":"insufficient_scope"},"Bearer error="+Q+"insufficient_scope"+Q+", scope="+Q+N[m]+Q)
  return self.out(200,{"result":{"content":[{"type":"text","text":m+" ok"}]}})
 do_GET=do_POST
ThreadingHTTPServer(("127.0.0.1",int(sys.argv[1]) if len(sys.argv)>1 else 9200),H).serve_forever()
