import http.client
import urllib.parse
from ._common import record

PROBE = 16
RULE = "MCP-ORIGIN-PARITY-1"
ORIGIN = "https://probe.invalid"

def skip(url, name, why, status=None, body=b""):
    return record(PROBE, name, "EXCLUDED", endpoint=url, prerequisite_met=False, limitation=why, http_status=status, body=body)

def originprobe(url, allowed=None):
    name = "origin validation parity on the sibling transport"
    try:
        parts = urllib.parse.urlsplit(url)
        if not parts.scheme or not parts.hostname:
            raise ValueError("target URL needs a scheme and a host")
        path = parts.path.rstrip("/")
        if not path.endswith("/mcp"):
            return skip(url, name, "target path does not end in mcp")
        sse = path[:-4] + "/sse"
        host = parts.hostname
        if allowed is not None and host not in allowed:
            return skip(url, name, "sibling host not declared")
        port = parts.port
        if port is None:
            port = 443 if parts.scheme == "https" else 80
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=10)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=10)
        hdrs = {"Origin": ORIGIN, "Access-Control-Request-Method": "POST"}
        try:
            conn.request("OPTIONS", sse, headers=hdrs)
            resp = conn.getresponse()
            status = resp.status
            acao = (resp.getheader("Access-Control-Allow-Origin") or "").strip()
            raw = resp.read(4096)
        finally:
            conn.close()
    except (OSError, http.client.HTTPException) as e:
        return skip(url, name, str(e))
    if status in (401, 403):
        return skip(url, name, "sibling answered " + str(status) + ", auth required so origin validation cannot be observed", status=status, body=raw)
    if status == 200 and acao.lower() == ORIGIN.lower():
        return record(PROBE, name, "FAIL", http_status=status, headers={'access-control-allow-origin': acao}, body=raw, endpoint=url, severity="MEDIUM", detail="sibling transport accepted a cross-origin preflight from " + ORIGIN + " and echoed it back")
    return skip(url, name, "sibling answered " + str(status) + " without echoing the supplied origin", status=status, body=raw)

def o_findings(target, rec):
    if rec.status != "FAIL":
        return []
    d = {}
    d["rule"] = RULE
    d["severity"] = rec.severity or "MEDIUM"
    d["confidence"] = "HIGH"
    d["title"] = rec.name
    d["file"] = target
    d["line"] = 0
    d["ref"] = RULE
    d["evidence"] = rec.detail or ""
    d["snippet"] = ""
    d["owasp"] = None
    d["is_live_finding"] = True
    d["request_method"] = "OPTIONS"
    d["request_body"] = ""
    d["response_status"] = rec.http_status or 0
    d["response_body"] = rec.body_excerpt or ""
    d["response_preview"] = rec.body_excerpt or ""
    d["interpretation"] = rec.detail or "Sibling transport does not validate Origin the way the primary path does"
    d["remediation"] = "Validate Origin on every transport the host serves, not only the primary MCP path"
    return [d]
