import json, sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from mcp_authscan.boundary import digest, row, report

WRITE = ("delete", "remove", "update", "create", "set", "drop", "exec", "run",
         "send", "post", "admin", "revoke", "write", "add", "modify", "transfer", "pay")

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "mcp-authscan-boundary", "version": "0.1"}}}

def call(url, payload, session=None, timeout=8):
    req = Request(url, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    req.add_header("User-Agent", "mcp-authscan-boundary/0.1")
    if session:
        req.add_header("Mcp-Session-Id", session)
    req.data = json.dumps(payload).encode()
    with urlopen(req, timeout=timeout) as resp:
        return resp.headers.get("Mcp-Session-Id"), resp.read(262144).decode("utf-8", "replace")

def parse(body):
    body = body.strip()
    if body.startswith("event:") or body.startswith("data:"):
        for line in body.splitlines():
            if line.startswith("data:"):
                body = line[5:].strip()
    try:
        return json.loads(body)
    except Exception:
        return None

def rows_from_tools(tools):
    out = []
    for i, t in enumerate(tools, 1):
        name = str(t.get("name", ""))
        ann = t.get("annotations") or {}
        ro = ann.get("readOnlyHint")
        dh = ann.get("destructiveHint")
        writes = any(w in name.lower() for w in WRITE)
        if not ann or (ro is None and dh is None):
            out.append(row("T%03d" % i, name, None, None, "no annotations published"))
            continue
        claims_readonly = (ro is True) or (dh is False)
        if claims_readonly and writes:
            out.append(row("T%03d" % i, name, "DENY", "ALLOW", "annotation vs tool name"))
        else:
            out.append(row("T%03d" % i, name, "DENY", "DENY", "annotation vs tool name"))
    return out

def main(argv):
    if len(argv) < 2:
        print("usage: python3 -m mcp_authscan.boundary_live URL")
        return 2
    url = argv[1]
    url = url if "://" in url else "https" + "://" + url
    session = None
    try:
        session, body = call(url, INIT)
    except HTTPError as e:
        print("BOUNDARY ABORT | initialize refused with %s | nothing tested" % e.code)
        return 2
    except (URLError, OSError) as e:
        print("BOUNDARY ABORT | %s unreachable | %s" % (url, getattr(e, "reason", e)))
        return 2
    init = parse(body) or {}
    if "result" not in init:
        print("BOUNDARY ABORT | initialize returned no result | nothing tested")
        return 2
    try:
        session2, body2 = call(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, session)
    except HTTPError as e:
        print("BOUNDARY ABORT | tools/list refused with %s | nothing tested" % e.code)
        return 2
    msg = parse(body2) or {}
    tools = ((msg.get("result") or {}).get("tools")) or []
    if not tools:
        print("BOUNDARY ABORT | no tools published | nothing tested")
        return 2
    rows = rows_from_tools(tools)
    code = report(rows)
    print("CONSISTENCY TARGET %s | %d tools | no credential used, no tool called | declaration check only" % (url, len(tools)))
    return code

main(sys.argv)
