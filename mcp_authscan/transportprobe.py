import http.client
import json
import urllib.parse
import importlib
import glob

CU = importlib.import_module("mcp" + chr(95) + "authscan." + chr(95) + "common")
record = CU.record
TID = 15
RULE = "MCP-TRANSPORT-1"
NL = chr(10)


def skip(url, name, why, status=None, body=b""):
    return record(TID, name, "EXCLUDED", endpoint=url, prerequisite_met=False, limitation=why, http_status=status, body=body)


def altprobe(url, allowed=None):
    name = "alternate transport on the same host"
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        if not parts.scheme or not host:
            raise ValueError("target URL needs a scheme and a host")
        path = parts.path.rstrip("/")
        if not path.endswith("/mcp"):
            return skip(url, name, "target path does not end in mcp")
        sse = path[:-4] + "/sse"
        if allowed is not None and host not in allowed:
            return skip(url, name, "sibling host not declared")
        port = parts.port
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)
        hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        try:
            conn.request("POST", sse, body=b"{}", headers=hdrs)
            resp = conn.getresponse()
            status = resp.status
            ctype = (resp.getheader("Content-Type") or "").lower()
            raw = resp.read(4096)
            seen = dict(resp.getheaders())
        finally:
            conn.close()
    except (OSError, http.client.HTTPException) as e:
        return skip(url, name, str(e))
    if status in (401, 403):
        return record(TID, name, "PASS", http_status=status, body=raw, headers=seen, endpoint=url, detail="sibling transport answered " + str(status) + " with authentication enforced")
    if status == 200:
        if "text/event-stream" in ctype:
            return record(TID, name, "FAIL", http_status=status, body=raw, headers=seen, endpoint=url, severity="HIGH", detail="sibling transport streamed with no credential")
        try:
            doc = json.loads(raw.decode("utf-8", "replace") or "{}")
        except ValueError:
            doc = None
        if isinstance(doc, dict) and "jsonrpc" in doc:
            return record(TID, name, "FAIL", http_status=status, body=raw, headers=seen, endpoint=url, severity="HIGH", detail="sibling transport answered JSON-RPC with no credential")
        return skip(url, name, "200 whose body cannot be graded", status=status, body=raw)
    return skip(url, name, "sibling transport answered " + str(status), status=status, body=raw)


def t_findings(target, rec):
    if rec.status != "FAIL":
        return []
    d = {}
    d["rule"] = RULE
    d["owasp"] = None
    d["severity"] = rec.severity or "HIGH"
    d["confidence"] = "HIGH"
    d["title"] = rec.name
    d["file"] = target
    d["line"] = 0
    d["ref"] = RULE
    d["evidence"] = rec.detail or ""
    d["snippet"] = ""
    d["is" + chr(95) + "live" + chr(95) + "finding"] = True
    d["request" + chr(95) + "method"] = "POST"
    d["request" + chr(95) + "body"] = "{}"
    d["response" + chr(95) + "status"] = rec.http_status or 0
    d["response" + chr(95) + "body"] = rec.body_excerpt or ""
    d["response" + chr(95) + "preview"] = rec.body_excerpt or ""
    d["interpretation"] = rec.detail or "A sibling transport answers with no credential"
    d["remediation"] = "Require authentication on every transport the host serves, not only the primary MCP path"
    return [d]


def patch():
    U = chr(95)
    d = glob.glob("mcp?authscan")[0]
    P = d + "/target_probes.py"
    src = open(P).read()
    if "transportprobe" in src:
        print("already wired")
        return
    I4 = chr(32) * 4
    I8 = chr(32) * 8
    lines = src.splitlines(True)
    start = None
    for i in range(len(lines)):
        if lines[i].startswith("def run" + U + "target" + U + "probes("):
            start = i
            break
    if start is None:
        raise SystemExit("run target probes not found")
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if lines[j] and not lines[j][0].isspace():
            end = j
            break
    out = []
    for ln in lines[start:end]:
        if ln.startswith(I4 + "records = [rec, "):
            out.append(I4 + "records = [rec, rate" + U + "rec, t" + U + "rec]" + NL)
            continue
        if ln.strip() == "return records, []":
            out.append(I8 + "return records, t" + U + "findings(target" + U + "url, t" + U + "rec)" + NL)
            continue
        if ln.startswith(I4 + "return records, [{"):
            out.append(I4 + "return records, t" + U + "findings(target" + U + "url, t" + U + "rec) + [{" + NL)
            continue
        out.append(ln)
        if "rate" + U + "limit" + U + "probe(target" + U + "url" in ln:
            out.append(I4 + "t" + U + "rec = altprobe(target" + U + "url, allowed=allowed" + U + "hosts)" + NL)
    print("".join(out))
    lines[start:end] = out
    new = "".join(lines)
    new = new + NL + "from mcp" + U + "authscan.transportprobe import altprobe, t" + U + "findings" + NL
    open(P, "w").write(new)
    M = d + "/monolith.py"
    ms = open(M).read()
    for q in (chr(34), chr(39)):
        old = q + "2026.11.11.1" + q
        if old in ms:
            ms = ms.replace(old, q + "2026.11.16.1" + q)
            break
    open(M, "w").write(ms)
    print("stamp bumped to 2026.11.16.1")
