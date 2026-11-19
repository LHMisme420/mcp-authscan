import base64, json, re, threading
import urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

U = chr(95)
Q = chr(34)
def K(p):
printf
%s\n
 return "".join(p)
printf
%s\n

printf
%s\n
SEC = "shockwave-secret-do-not-reuse"
printf
%s\n
POSTS = []
printf
%s\n
CTX = {}
printf
%s\n

printf
%s\n
def snd(h, code, hdrs, doc):
printf
%s\n
 b = json.dumps(doc).encode() if doc is not None else b""
printf
%s\n
 getattr(h, K("send", U, "response"))(code)
printf
%s\n
 for k, v in hdrs:
printf
%s\n
 getattr(h, K("send", U, "header"))(k, v)
printf
%s\n
 getattr(h, K("send", U, "header"))("Content-Length", str(len(b)))
printf
%s\n
 getattr(h, K("end", U, "headers"))()
printf
%s\n
 if b:
printf
%s\n
 h.wfile.write(b)
printf
%s\n

printf
%s\n
def tget(h):
printf
%s\n
 t = CTX["t"]
printf
%s\n
 a = CTX["a"]
printf
%s\n
 if h.path.startswith("/mcp"):
printf
%s\n
 p = t + "/.well-known/oauth-protected-resource"
printf
%s\n
 hdr = "Bearer " + K("resource", U, "metadata") + "=" + Q + p + Q
printf
%s\n
 snd(h, 401, [(K("WWW", U, "Authenticate"), hdr)], {"error": "unauthorized"})
printf
%s\n
 return
printf
%s\n
 if h.path.startswith("/.well-known"):
printf
%s\n
 snd(h, 200, [], {K("resource"): t + "/mcp", K("authorization", U, "servers"): [a]})
printf
%s\n
 return
printf
%s\n
 snd(h, 404, [], None)
printf
%s\n

printf
%s\n
def aget(h):
printf
%s\n
 a = CTX["a"]
printf
%s\n
 if not h.path.startswith("/.well-known/oauth-authorization-server"):
printf
%s\n
 snd(h, 404, [], None)
printf
%s\n
 return
printf
%s\n
 doc = {K("authorization", U, "endpoint"): a + "/auth", K("token", U, "endpoint"): a + "/tok", "issuer": a}
printf
%s\n
 snd(h, 200, [], doc)
printf
%s\n

printf
%s\n
def apost(h):
printf
%s\n
 n = int(h.headers.get("Content-Length") or 0)
printf
%s\n
 h.rfile.read(n)
printf
%s\n
 POSTS.append(getattr(h.server, K("server", U, "address"))[0])
printf
%s\n
 snd(h, 400, [], {"error": K("invalid", U, "grant")})
printf
%s\n

printf
%s\n
def quiet(a):
 pass

TG = type("TG", (BaseHTTPRequestHandler,), {K("do", U, "GET"): tget, K("log", U, "message"): quiet})
AG = type("AG", (BaseHTTPRequestHandler,), {K("do", U, "GET"): aget, K("do", U, "POST"): apost, K("log", U, "message"): quiet})

def probe():
 t = CTX["t"]
 POSTS.clear()
 try:
 urllib.request.urlopen(t + "/mcp", timeout=5)
 return "EXCLUDED", "target answered with no challenge"
 except urllib.error.HTTPError as e:
 ch = e.headers.get("WWW-Authenticate") or ""
 m = re.search(K("resource", U, "metadata") + "=" + Q + "([^" + Q + "]+)" + Q, ch)
 if not m:
 return "EXCLUDED", "challenge has no metadata pointer"
 pr = json.load(urllib.request.urlopen(m.group(1), timeout=5))
 a = (pr.get(K("authorization", U, "servers")) or [""])[0].rstrip("/")
 url = a + "/.well-known/oauth-authorization-server"
 md = json.load(urllib.request.urlopen(url, timeout=5))
 if md.get("issuer") != url:
 return "SHIELDED", "refused: issuer is not the URL it was fetched from"
 pay = urllib.parse.urlencode({K("grant", U, "type"): K("client", U, "credentials")}).encode()
 cred = base64.b64encode(("cid:" + SEC).encode()).decode()
 rq = urllib.request.Request(md[K("token", U, "endpoint")], data=pay)
 rq.addheader("Authorization", "Basic " + cred)
printf
%s\n
 rq.addheader("Content-Type", "application/x-www-form-urlencoded")
 try:
 urllib.request.urlopen(rq, timeout=5)
 except urllib.error.HTTPError:
 pass
 if not POSTS:
 return "EXCLUDED", "token request never arrived"
 if POSTS[-1] != "127.0.0.1":
 return "EXPOSED", "client secret delivered to " + POSTS[-1]
 return "SHIELDED", "client secret stayed home"

def runcase(host):
 CTX.clear()
 ta = ThreadingHTTPServer((host, 0), AG)
 tt = ThreadingHTTPServer(("127.0.0.1", 0), TG)
 CTX["a"] = "http://" + host + ":" + str(getattr(ta, K("server", U, "address"))[1])
 CTX["t"] = "http://127.0.0.1:" + str(getattr(tt, K("server", U, "address"))[1])
 x = threading.Thread(target=getattr(ta, K("serve", U, "forever")), daemon=True)
 y = threading.Thread(target=getattr(tt, K("serve", U, "forever")), daemon=True)
 x.start()
 y.start()
 try:
 return probe()
 finally:
 ta.shutdown()
 tt.shutdown()

v1, d1 = runcase("127.0.0.1")
print("01 control " + v1.ljust(9) + d1)
v2, d2 = runcase("127.0.0.2")
print("02 decoy " + v2.ljust(9) + d2)
print("control shielded: " + str(v1 == "SHIELDED"))
print("decoy exposed: " + str(v2 == "EXPOSED"))
raise SystemExit(0 if (v1 == "SHIELDED" and v2 == "EXPOSED") else 1)
