import json, socket, threading, hashlib, sys

TOOLS = {"read docs": "read", "list users": "read", "write file": "write", "delete account": "admin", "audit export": "admin"}
DECL = {"read docs": "read", "list users": "read", "write file": "write", "delete account": "admin", "audit export": None}
TOKENS = {"tokread": ("read",), "tokrw": ("read", "write")}
POL = {"tokread": ("read docs",), "tokrw": ("read docs", "write file")}
PORT = 8799

def handle(auth, body):
    try:
        req = json.loads(body.decode() or "{}")
    except ValueError:
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
    i = req.get("id")
    m = req.get("method")
    sc = TOKENS.get(auth)
    if m == "initialize":
        return {"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-06-18", "serverInfo": {"name": "blast fixture"}}}
    if sc is None:
        return {"jsonrpc": "2.0", "id": i, "error": {"code": -32001, "message": "unauthorized"}}
    if m == "tools/list":
        out = list()
        for t in sorted(TOOLS):
            row = {"name": t}
            if DECL.get(t) is not None:
                row["declared scope"] = DECL.get(t)
            out.append(row)
        return {"jsonrpc": "2.0", "id": i, "result": {"tools": out}}
    if m == "tools/call":
        name = (req.get("params") or {}).get("name")
        need = TOOLS.get(name)
        if need is None:
            return {"jsonrpc": "2.0", "id": i, "error": {"code": -32602, "message": "unknown tool"}}
        if need not in sc:
            return {"jsonrpc": "2.0", "id": i, "error": {"code": -32002, "message": "scope " + need + " not granted"}}
        return {"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "ok " + name}]}}
    return {"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "method not found"}}

def serve():
    s = socket.socket()
    s.setsockopt(1, 2, 1)
    s.bind(("127.0.0.1", PORT))
    s.listen(16)
    while True:
        c, a = s.accept()
        try:
            data = b""
            while b"\r\n\r\n" not in data:
                ch = c.recv(4096)
                if not ch:
                    break
                data += ch
            head, sep, body = data.partition(b"\r\n\r\n")
            lines = head.split(b"\r\n")
            n = 0
            auth = ""
            for ln in lines[1:]:
                k, x, v = ln.partition(b":")
                kl = k.strip().lower()
                if kl == b"content-length":
                    n = int(v.strip() or 0)
                if kl == b"authorization":
                    auth = v.strip().decode().replace("Bearer ", "")
            while len(body) < n:
                ch = c.recv(4096)
                if not ch:
                    break
                body += ch
            resp = handle(auth, body)
            out = json.dumps(resp).encode()
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + str(len(out)).encode() + b"\r\nConnection: close\r\n\r\n" + out)
        except OSError:
            pass
        finally:
            c.close()

def post(tok, obj):
    b = json.dumps(obj).encode()
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    h = "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: " + str(len(b)) + "\r\nConnection: close\r\n"
    if tok:
        h += "Authorization: Bearer " + tok + "\r\n"
    s.sendall(h.encode() + b"\r\n" + b)
    data = b""
    while True:
        ch = s.recv(4096)
        if not ch:
            break
        data += ch
    s.close()
    head, sep, body = data.partition(b"\r\n\r\n")
    try:
        return json.loads(body.decode() or "{}")
    except ValueError:
        return {}

def observe(tok):
    seen = list()
    for t in sorted(TOOLS):
        r = post(tok, {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": t, "arguments": {}}})
        if "result" in r:
            seen.append(t)
    return seen

def grade(listed, seen, intended):
    rows = list()
    for t in sorted(listed):
        if t in seen:
            v = "VERIFIED INTENDED" if t in intended else "VERIFIED EXCESS"
        elif DECL.get(t) is None:
            v = "UNKNOWN"
        else:
            v = "POTENTIAL DECLARED"
        rows.append({"tool": t, "verdict": v})
    return rows

def digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()

def main():
    th = threading.Thread(target=serve)
    th.daemon = True
    th.start()
    listed = sorted(TOOLS)
    rows = list()
    for tok in sorted(TOKENS):
        seen = observe(tok)
        for r in grade(listed, seen, POL.get(tok)):
            r["identity"] = tok
            rows.append(r)
    for r in rows:
        print(r.get("identity"), r.get("tool"), "->", r.get("verdict"))
    print("DIGEST", digest(rows))
    want = dict()
    want[("tokread", "read docs")] = "VERIFIED INTENDED"
    want[("tokread", "list users")] = "VERIFIED EXCESS"
    want[("tokread", "delete account")] = "POTENTIAL DECLARED"
    want[("tokread", "audit export")] = "UNKNOWN"
    want[("tokrw", "write file")] = "VERIFIED INTENDED"
    want[("tokrw", "delete account")] = "POTENTIAL DECLARED"
    got = dict()
    for r in rows:
        got[(r.get("identity"), r.get("tool"))] = r.get("verdict")
    bad = list()
    for k in want:
        if got.get(k) != want.get(k):
            bad.append(k[0] + "/" + k[1])
    if bad:
        print("RED", ",".join(bad))
        return 1
    print("GREEN", len(want), "of", len(want))
    return 0

for t in list(TOKENS):
    POL[t]=tuple(json.load(open("bench/answer-key/fixtures/policy-"+t+".json")).get("intended") or ())
sys.exit(main())