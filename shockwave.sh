bash
printf '' > shockwave.py
printf '%s\n' 'import base64, json, re, threading' >> shockwave.py
printf '%s\n' 'import urllib.error, urllib.parse, urllib.request' >> shockwave.py
printf '%s\n' 'from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer' >> shockwave.py
printf '%s\n' '' >> shockwave.py
printf '%s\n' 'U = chr(95)' >> shockwave.py
printf '%s\n' 'Q = chr(34)' >> shockwave.py
printf '%s\n' 'def K(p):' >> shockwave.py printf '%s\n' ' return "".join(p)' >> shockwave.py printf '%s\n' '' >> shockwave.py printf '%s\n' 'SEC = "shockwave-secret-do-not-reuse"' >> shockwave.py printf '%s\n' 'POSTS = []' >> shockwave.py printf '%s\n' 'CTX = {}' >> shockwave.py printf '%s\n' '' >> shockwave.py printf '%s\n' 'def snd(h, code, hdrs, doc):' >> shockwave.py printf '%s\n' ' b = json.dumps(doc).encode() if doc is not None else b""' >> shockwave.py printf '%s\n' ' getattr(h, K("send", U, "response"))(code)' >> shockwave.py printf '%s\n' ' for k, v in hdrs:' >> shockwave.py printf '%s\n' ' getattr(h, K("send", U, "header"))(k, v)' >> shockwave.py printf '%s\n' ' getattr(h, K("send", U, "header"))("Content-Length", str(len(b)))' >> shockwave.py printf '%s\n' ' getattr(h, K("end", U, "headers"))()' >> shockwave.py printf '%s\n' ' if b:' >> shockwave.py printf '%s\n' ' h.wfile.write(b)' >> shockwave.py printf '%s\n' '' >> shockwave.py printf '%s\n' 'def tget(h):' >> shockwave.py printf '%s\n' ' t = CTX["t"]' >> shockwave.py printf '%s\n' ' a = CTX["a"]' >> shockwave.py printf '%s\n' ' if h.path.startswith("/mcp"):' >> shockwave.py printf '%s\n' ' p = t + "/.well-known/oauth-protected-resource"' >> shockwave.py printf '%s\n' ' hdr = "Bearer " + K("resource", U, "metadata") + "=" + Q + p + Q' >> shockwave.py printf '%s\n' ' snd(h, 401, [(K("WWW", U, "Authenticate"), hdr)], {"error": "unauthorized"})' >> shockwave.py printf '%s\n' ' return' >> shockwave.py printf '%s\n' ' if h.path.startswith("/.well-known"):' >> shockwave.py printf '%s\n' ' snd(h, 200, [], {K("resource"): t + "/mcp", K("authorization", U, "servers"): [a]})' >> shockwave.py printf '%s\n' ' return' >> shockwave.py printf '%s\n' ' snd(h, 404, [], None)' >> shockwave.py printf '%s\n' '' >> shockwave.py printf '%s\n' 'def aget(h):' >> shockwave.py printf '%s\n' ' a = CTX["a"]' >> shockwave.py printf '%s\n' ' if not h.path.startswith("/.well-known/oauth-authorization-server"):' >> shockwave.py printf '%s\n' ' snd(h, 404, [], None)' >> shockwave.py printf '%s\n' ' return' >> shockwave.py printf '%s\n' ' doc = {K("authorization", U, "endpoint"): a + "/auth", K("token", U, "endpoint"): a + "/tok", "issuer": a}' >> shockwave.py printf '%s\n' ' snd(h, 200, [], doc)' >> shockwave.py printf '%s\n' '' >> shockwave.py printf '%s\n' 'def apost(h):' >> shockwave.py printf '%s\n' ' n = int(h.headers.get("Content-Length") or 0)' >> shockwave.py printf '%s\n' ' h.rfile.read(n)' >> shockwave.py printf '%s\n' ' POSTS.append(getattr(h.server, K("server", U, "address"))[0])' >> shockwave.py printf '%s\n' ' snd(h, 400, [], {"error": K("invalid", U, "grant")})' >> shockwave.py printf '%s\n' '' >> shockwave.py printf '%s\n' 'def quiet(a):' >> shockwave.py
printf '%s\n' ' pass' >> shockwave.py
printf '%s\n' '' >> shockwave.py
printf '%s\n' 'TG = type("TG", (BaseHTTPRequestHandler,), {K("do", U, "GET"): tget, K("log", U, "message"): quiet})' >> shockwave.py
printf '%s\n' 'AG = type("AG", (BaseHTTPRequestHandler,), {K("do", U, "GET"): aget, K("do", U, "POST"): apost, K("log", U, "message"): quiet})' >> shockwave.py
printf '%s\n' '' >> shockwave.py
printf '%s\n' 'def probe():' >> shockwave.py
printf '%s\n' ' t = CTX["t"]' >> shockwave.py
printf '%s\n' ' POSTS.clear()' >> shockwave.py
printf '%s\n' ' try:' >> shockwave.py
printf '%s\n' ' urllib.request.urlopen(t + "/mcp", timeout=5)' >> shockwave.py
printf '%s\n' ' return "EXCLUDED", "target answered with no challenge"' >> shockwave.py
printf '%s\n' ' except urllib.error.HTTPError as e:' >> shockwave.py
printf '%s\n' ' ch = e.headers.get("WWW-Authenticate") or ""' >> shockwave.py
printf '%s\n' ' m = re.search(K("resource", U, "metadata") + "=" + Q + "([^" + Q + "]+)" + Q, ch)' >> shockwave.py
printf '%s\n' ' if not m:' >> shockwave.py
printf '%s\n' ' return "EXCLUDED", "challenge has no metadata pointer"' >> shockwave.py
printf '%s\n' ' pr = json.load(urllib.request.urlopen(m.group(1), timeout=5))' >> shockwave.py
printf '%s\n' ' a = (pr.get(K("authorization", U, "servers")) or [""])[0].rstrip("/")' >> shockwave.py
printf '%s\n' ' url = a + "/.well-known/oauth-authorization-server"' >> shockwave.py
printf '%s\n' ' md = json.load(urllib.request.urlopen(url, timeout=5))' >> shockwave.py
printf '%s\n' ' if md.get("issuer") != url:' >> shockwave.py
printf '%s\n' ' return "SHIELDED", "refused: issuer is not the URL it was fetched from"' >> shockwave.py
printf '%s\n' ' pay = urllib.parse.urlencode({K("grant", U, "type"): K("client", U, "credentials")}).encode()' >> shockwave.py
printf '%s\n' ' cred = base64.b64encode(("cid:" + SEC).encode()).decode()' >> shockwave.py
printf '%s\n' ' rq = urllib.request.Request(md[K("token", U, "endpoint")], data=pay)' >> shockwave.py
printf '%s\n' ' rq.addheader("Authorization", "Basic " + cred)' >> shockwave.py printf '%s\n' ' rq.addheader("Content-Type", "application/x-www-form-urlencoded")' >> shockwave.py
printf '%s\n' ' try:' >> shockwave.py
printf '%s\n' ' urllib.request.urlopen(rq, timeout=5)' >> shockwave.py
printf '%s\n' ' except urllib.error.HTTPError:' >> shockwave.py
printf '%s\n' ' pass' >> shockwave.py
printf '%s\n' ' if not POSTS:' >> shockwave.py
printf '%s\n' ' return "EXCLUDED", "token request never arrived"' >> shockwave.py
printf '%s\n' ' if POSTS[-1] != "127.0.0.1":' >> shockwave.py
printf '%s\n' ' return "EXPOSED", "client secret delivered to " + POSTS[-1]' >> shockwave.py
printf '%s\n' ' return "SHIELDED", "client secret stayed home"' >> shockwave.py
printf '%s\n' '' >> shockwave.py
printf '%s\n' 'def runcase(host):' >> shockwave.py
printf '%s\n' ' CTX.clear()' >> shockwave.py
printf '%s\n' ' ta = ThreadingHTTPServer((host, 0), AG)' >> shockwave.py
printf '%s\n' ' tt = ThreadingHTTPServer(("127.0.0.1", 0), TG)' >> shockwave.py
printf '%s\n' ' CTX["a"] = "http://" + host + ":" + str(getattr(ta, K("server", U, "address"))[1])' >> shockwave.py
printf '%s\n' ' CTX["t"] = "http://127.0.0.1:" + str(getattr(tt, K("server", U, "address"))[1])' >> shockwave.py
printf '%s\n' ' x = threading.Thread(target=getattr(ta, K("serve", U, "forever")), daemon=True)' >> shockwave.py
printf '%s\n' ' y = threading.Thread(target=getattr(tt, K("serve", U, "forever")), daemon=True)' >> shockwave.py
printf '%s\n' ' x.start()' >> shockwave.py
printf '%s\n' ' y.start()' >> shockwave.py
printf '%s\n' ' try:' >> shockwave.py
printf '%s\n' ' return probe()' >> shockwave.py
printf '%s\n' ' finally:' >> shockwave.py
printf '%s\n' ' ta.shutdown()' >> shockwave.py
printf '%s\n' ' tt.shutdown()' >> shockwave.py
printf '%s\n' '' >> shockwave.py
printf '%s\n' 'v1, d1 = runcase("127.0.0.1")' >> shockwave.py
printf '%s\n' 'print("01 control " + v1.ljust(9) + d1)' >> shockwave.py
printf '%s\n' 'v2, d2 = runcase("127.0.0.2")' >> shockwave.py
printf '%s\n' 'print("02 decoy " + v2.ljust(9) + d2)' >> shockwave.py
printf '%s\n' 'print("control shielded: " + str(v1 == "SHIELDED"))' >> shockwave.py
printf '%s\n' 'print("decoy exposed: " + str(v2 == "EXPOSED"))' >> shockwave.py
printf '%s\n' 'raise SystemExit(0 if (v1 == "SHIELDED" and v2 == "EXPOSED") else 1)' >> shockwave.py
python3 shockwave.py
