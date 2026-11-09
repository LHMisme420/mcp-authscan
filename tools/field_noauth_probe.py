import sys, json, time, urllib.request, urllib.error
from urllib.parse import urlparse

UA = "mcp-authscan-field/0.1 (+github.com/LHMisme420/mcp-authscan)"
BODY = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "authscan-field", "version": "0"}}}

def probe(url, timeout):
    req = urllib.request.Request(url, data=json.dumps(BODY).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": UA},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, text, hdr = r.status, r.read(200000).decode("utf-8", "replace"), r.headers.get("WWW-Authenticate")
    except urllib.error.HTTPError as e:
        code, text, hdr = e.code, "", e.headers.get("WWW-Authenticate")
    except Exception as e:
        return "UNREACHABLE", None, repr(e)[:120]
    if hdr or code in (401, 403):
        return "CHALLENGED", code, "WWW-Authenticate" if hdr else "status only"
    if code == 200:
        payload = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                line = line[5:].strip()
            if not line:
                continue
            try:
                cand = json.loads(line)
            except ValueError:
                continue
            if isinstance(cand, dict) and isinstance(cand.get("result"), dict):
                payload = cand["result"]
        if payload and ("serverInfo" in payload or "protocolVersion" in payload):
            return "NOAUTH_INIT", code, "initialize accepted with no credentials"
        return "NOT_MCP", code, "200 without an initialize result"
    return "NOT_MCP", code, "status " + str(code)

def main():
    src, out = sys.argv[1], sys.argv[2]
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 8.0
    urls, seen, rows = [], set(), []
    for line in open(src):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            j = json.loads(line)
            u = j.get("url") or j.get("endpoint") or ""
        except ValueError:
            u = line
        u = u.strip()
        if not u.startswith("http"):
            continue
        h = urlparse(u).netloc
        if h in seen:
            continue
        seen.add(h)
        urls.append(u)
    print("unique hosts:", len(urls))
    counts = {}
    with open(out, "w") as f:
        for u in urls:
            v, code, why = probe(u, timeout)
            counts[v] = counts.get(v, 0) + 1
            row = {"endpoint": u, "verdict": v, "status": code, "reason": why}
            f.write(json.dumps(row) + "\n")
            f.flush()
            print(v, u, flush=True)
            time.sleep(1.0)
    print(json.dumps(counts, indent=2, sort_keys=True))

main()
