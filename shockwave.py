
python
import base64, json, re, threading
import urllib.error, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

U = chr(95)
Q = chr(34)

def K(*p):
return "".join(p)

SEC = "shockwave-secret-do-not-reuse"
CID = "shockwave-client"
POSTS = []
CTX = {}

CASES = [
("01ctl", "127.0.0.1", "echo", "SHIELDED"),
("02decoy", "127.0.0.2", "echo", "EXPOSED"),
("03foreign", "127.0.0.2", "target", "SHIELDED"),
("04slash", "127.0.0.2", "slash", "SHIELDED"),
("05down", "127.0.0.2", "down", "SHIELDED"),
("06noiss", "127.0.0.2", "none", "SHIELDED"),
]

def ival(kind, a, t):
if kind == "echo":
return a
if kind == "target":
return t
if kind == "slash":
return a + "/"
if kind == "down":
return a.replace("http://", "https://")
return None

def snd(h, code, hdrs, doc):
b = json.dumps(doc).encode() if doc is not None else b""
getattr(h, K("send", U, "response"))(code)
for k, v in hdrs:
getattr(h, K("send", U, "header"))(k, v)
getattr(h, K("send", U, "header"))("Content-Length", str(len(b)))
getattr(h, K("end", U, "headers"))()
if b:
h.wfile.write(b)

def tget(h):
t = CTX["t"]
a = CTX["a"]
if h.path.startswith("/mcp"):
p = t + "/.well-known/oauth-protected-resource"
hdr = "Bearer " + K("resource", U, "metadata") + "=" + Q + p + Q
snd(h, 401, [(K("WWW", U, "Authenticate"), hdr)], {"error": "unauthorized"})
return
if h.path.startswith("/.well-known"):
snd(h, 200, [], {K("resource"): t + "/mcp", K("authorization", U, "servers"): [a]})
return
snd(h, 404, [], None)

def aget(h):
a = CTX["a"]
if not h.path.startswith("/.well-known/oauth-authorization-server"):
snd(h, 404, [], None)
return
doc = {
K("authorization", U, "endpoint"): a + "/auth",
K("token", U, "endpoint"): a + "/tok",
"issuer": ival(CTX["k"], a, CTX["t"]),
}
if doc["issuer"] is None:
del doc["issuer"]
snd(h, 200, [], doc)

def apost(h):
n = int(h.headers.get("Content-Length") or 0)
h.rfile.read(n)
POSTS.append(getattr(h.server, K("server", U, "address"))[0])
snd(h, 400, [], {"error": K("invalid", U, "grant")})

def quiet(*x):
return None

def probe():
t = CTX["t"]
POSTS.clear()
try:
urllib.request.urlopen(t + "/mcp", timeout=5)
return "EXCLUDED", "target answered with no challenge"
except urllib.error.HTTPError as e:
ch = e.headers.get("WWW-Authenticate") or ""
except Exception as e:
return "EXCLUDED", "target unreachable " + type(e).name
m = re.search(K("resource", U, "metadata") + "=" + Q + "([^" + Q + "]+)" + Q, ch)
if not m:
return "EXCLUDED", "challenge has no metadata pointer"
try:
pr = json.load(urllib.request.urlopen(m.group(1), timeout=5))
except Exception as e:
return "EXCLUDED", "resource metadata unreadable " + type(e).name
srv = pr.get(K("authorization", U, "servers")) or []
if not srv:
return "EXCLUDED", "metadata names no authorization server"
a = srv[0].rstrip("/")
url = a + "/.well-known/oauth-authorization-server"
try:
md = json.load(urllib.request.urlopen(url, timeout=5))
except Exception as e:
return "EXCLUDED", "server metadata unreadable " + type(e).name
te = md.get(K("token", U, "endpoint"))
if not te:
return "EXCLUDED", "metadata carries no token endpoint"
iss = md.get("issuer")
if iss != url:
return "SHIELDED", "refused before sending, issuer is not the fetch URL"
pay = urllib.parse.urlencode({K("grant", U, "type"): K("client", U, "credentials")}).encode()
cred = base64.b64encode((CID + ":" + SEC).encode()).decode()
rq = urllib.request.Request(te, data=pay, headers={
"Authorization": "Basic " + cred,
"Content-Type": "application/x-www-form-urlencoded",
})
try:
urllib.request.urlopen(rq, timeout=5)
except urllib.error.HTTPError:
pass
except Exception as e:
return "EXCLUDED", "token request failed " + type(e).name
if not POSTS:
return "EXCLUDED", "token request never arrived"
if POSTS[-1] != "127.0.0.1":
return "EXPOSED", "client secret delivered to " + POSTS[-1]
return "SHIELDED", "client secret stayed on 127.0.0.1"

def runcase(c):
CTX.clear()
CTX["k"] = c[2]
ta = ThreadingHTTPServer((c[1], 0), AG)
tt = ThreadingHTTPServer(("127.0.0.1", 0), TG)
ta.daemonthreads = True tt.daemonthreads = True
CTX["a"] = "http://" + c[1] + ":" + str(getattr(ta, K("server", U, "address"))[1])
CTX["t"] = "http://127.0.0.1:" + str(getattr(tt, K("server", U, "address"))[1])
xa = threading.Thread(target=getattr(ta, K("serve", U, "forever")), daemon=True)
xt = threading.Thread(target=getattr(tt, K("serve", U, "forever")), daemon=True)
xa.start()
xt.start()
try:
return probe()
finally:
for s in (ta, tt):
try:
getattr(s, "shutdown")()
except Exception:
pass
try:
getattr(s, K("server", U, "close"))()
except Exception:
pass

TG = type("TG", (BaseHTTPRequestHandler,), {
K("do", U, "GET"): tget,
K("log", U, "message"): quiet,
})
AG = type("AG", (BaseHTTPRequestHandler,), {
K("do", U, "GET"): aget,
K("do", U, "POST"): apost,
K("log", U, "message"): quiet,
})

hits = 0
miss = 0
exc = 0
for c in CASES:
v, d = runcase(c)
if v == "EXCLUDED":
exc += 1
mark = "excluded"
elif v == c[3]:
hits += 1
mark = "hit"
else:
miss += 1
mark = "MISS"
print(c[0].ljust(11) + v.ljust(10) + mark.ljust(9) + d)
print("")
print("score " + str(hits) + " hit, " + str(miss) + " miss, " + str(exc) + " excluded, of " + str(len(CASES)))
raise SystemExit(0 if miss == 0 else 1)
