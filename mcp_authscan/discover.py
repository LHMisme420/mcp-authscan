import json,sys,threading,http.server,urllib.request as u,urllib.error as e
S="ht"+"tps"
VER=["2026-07-28","2025-06-18","2025-03-26"]
UA="mcp-authscan-field/0.1 research"
PREC=["DISCOVER","NOT_IMPLEMENTED","VERSION_REJECT","HEADER_MISMATCH","BAD_REQUEST","INVALID_REQUEST","GATED","UNPARSED"]
def body():
 return json.dumps({"jsonrpc":"2.0","id":1,"method":"server/discover"}).encode()
def hdrs(v):
 return {"User-Agent":UA,"Content-Type":"application/json",
 "Accept":"application/json, text/event-stream",
 "Mcp-Method":"server/discover","mcp-protocol-version":v}
def unwrap(text):
 frames=[]
 for ln in text.splitlines():
  ln=ln.strip()
  if ln.startswith("data:"):
   frames.append(ln[5:].strip())
 for f in reversed(frames or [text]):
  try:
   return json.loads(f)
  except Exception:
   continue
 return None
def classify(text):
 o=unwrap(text)
 if o is None:
  return "UNPARSED"
 if not isinstance(o,dict):
  return "UNPARSED"
 if "error" not in o:
  return "DISCOVER" if "result" in o else "UNPARSED"
 err=o["error"]
 code=err.get("code") if isinstance(err,dict) else None
 msg=str(err.get("message","")) if isinstance(err,dict) else ""
 m=msg.lower()
 if code==-32000:return "GATED"
 if code in (-32601,):return "NOT_IMPLEMENTED"
 if code==-32600:
  return "VERSION_REJECT" if ("version" in m or "unsupported" in m) else "INVALID_REQUEST"
 if code==-32020 or "mismatch" in m:return "HEADER_MISMATCH"
 if code==-32602:return "BAD_REQUEST"
 return "ERROR_"+str(code)
def probe(url,versions=None,timeout=12):
 vs=versions or VER
 out={"url":url,"verdict":"UNREACHABLE","version":None,"ladder":[]}
 for v in vs:
  q=u.Request(url,data=body(),headers=hdrs(v),method="POST")
  try:
   r=u.urlopen(q,timeout=timeout)
   st=r.status
   tx=r.read(4000).decode("utf-8","replace")
  except e.HTTPError as x:
   st=x.code
   try:tx=x.read(4000).decode("utf-8","replace")
   except Exception:tx=""
  except Exception as ex:
   out["detail"]=str(ex)[:120]
   return out
  if st in (401,403):cd="GATED"
  elif st>=500:cd="HTTP_"+str(st)
  else:cd=classify(tx)
  out["ladder"].append({"version":v,"status":st,"verdict":cd})
  if cd=="DISCOVER":
   out["verdict"]="DISCOVER"
   out["version"]=v
   return out
 seen=[x["verdict"] for x in out["ladder"]]
 for p in PREC:
  if p in seen:
   out["verdict"]=p
   return out
 out["verdict"]=seen[0] if seen else "UNREACHABLE"
 return out
class F(http.server.BaseHTTPRequestHandler):
 def log_message(self,*a):pass
 def snd(self,st,txt,ct="application/json"):
  b=txt.encode()
  self.send_response(st)
  self.send_header("Content-Type",ct)
  self.send_header("Content-Length",str(len(b)))
  self.end_headers()
  self.wfile.write(b)
 def do_POST(self):
  n=int(self.headers.get("Content-Length") or 0)
  self.rfile.read(n)
  p=self.path
  if p=="/discover":self.snd(200,'{"jsonrpc":"2.0","id":1,"result":{"ok":1}}')
  elif p=="/notimpl":self.snd(200,'{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}')
  elif p=="/version":self.snd(400,'{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Unsupported MCP-Protocol-Version"}}')
  elif p=="/gated":self.snd(401,'{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Authentication required"}}')
  elif p=="/html":self.snd(200,"<html>docs</html>","text/html")
  elif p=="/err200":self.snd(200,'{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid request parameters"}}')
  else:self.snd(404,"{}")
def selftest():
 srv=http.server.ThreadingHTTPServer(("127.0.0.1",0),F)
 threading.Thread(target=srv.serve_forever,daemon=True).start()
 base="ht"+"tp"+"://127.0.0.1:"+str(srv.server_address[1])
 cases=[("/discover","DISCOVER"),("/notimpl","NOT_IMPLEMENTED"),
 ("/version","VERSION_REJECT"),("/gated","GATED"),
 ("/html","UNPARSED"),("/err200","BAD_REQUEST")]
 bad=0
 for p,want in cases:
  got=probe(base+p)["verdict"]
  ok=got==want
  bad+=0 if ok else 1
  print(("PASS " if ok else "FAIL ")+p+" want="+want+" got="+got)
 srv.shutdown()
 print("selftest "+("PASS" if bad==0 else "FAIL "+str(bad)+" case(s)"))
 return 1 if bad else 0
if "--selftest" in sys.argv:
 sys.exit(selftest())
if len(sys.argv)>1:
 print(json.dumps(probe(sys.argv[1]),indent=1))
