"""Content observations over an established MCP session.

Read-only. Emits a finding when tool, prompt or resource metadata carries
instruction-like content or names a private path. Never passes. Never
contributes to the PASS plus FAIL coverage denominator.
"""
import json
import re

from mcp_authscan import mcp_session
from mcp_authscan.owasp_mapping import tag

CONTENT_PROBE_VERSION = "2026.11.03.1"

DIRECTIVE = re.compile(
    r"(?i)\b(ignore (all )?(previous|prior|above)|do not (tell|mention|reveal)"
    r"|you must|always (call|use|read|send)"
    r"|before (using|calling) this tool)\b")

SECRETISH = re.compile(
    r"(?i)(~/\.ssh|id_rsa|/etc/passwd|/etc/shadow|\.env\b"
    r"|api[_-]?key|bearer token|private key)")

SYSTEM_PATH = re.compile(r"(?i)^file:///(etc|root|home|proc|sys)/")

def _excerpt(text, limit=160):
    flat = " ".join(text.split())
    return flat[:limit]

def _text_of(item):
    bits = []
    for k in ("name", "description", "title"):
        v = item.get(k)
        if isinstance(v, str):
            bits.append(v)
    return " ".join(bits)

def _parse(status, headers, raw):
    ctype = ""
    try:
        for k, v in headers.items():
            if k.lower() == "content-type":
                ctype = v.lower()
                break
    except Exception:
        pass
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in ctype:
        text = "\n".join(l[5:].strip() for l in text.splitlines()
                         if l.startswith("data:"))
    try:
        return json.loads(text)
    except Exception:
        return None

def _finding(rule, sev, title, endpoint, evidence):
    return {
        "rule": rule, "owasp": tag(rule), "severity": sev,
        "confidence": "MEDIUM", "title": title, "file": endpoint,
        "line": 0, "ref": rule, "evidence": evidence, "snippet": "",
    }

def _scan(endpoint, key, items):
    found = []
    for item in items:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("uri") or "(unnamed)"
        text = _text_of(item)
        uri = item.get("uri")
        if DIRECTIVE.search(text):
            found.append(_finding(
                "MCPC-1", "HIGH", "directive-like content in metadata",
                endpoint, "%s: %s" % (name, _excerpt(text))))
        if isinstance(uri, str) and SYSTEM_PATH.match(uri):
            found.append(_finding(
                "MCPC-2", "HIGH", "resource exposes a system path",
                endpoint, "%s -> %s" % (name, uri)))
        elif isinstance(uri, str) and SECRETISH.search(uri):
            found.append(_finding(
                "MCPC-2", "MEDIUM", "private path named in metadata",
                endpoint, "%s: %s" % (name, _excerpt(uri))))
    return found

LISTS = (("tools/list", "tools"), ("prompts/list", "prompts"),
         ("resources/list", "resources"))

def observe(endpoint, token=None, allow_private=None, allowed_hosts=None):
    session = mcp_session.open_session(
        endpoint, token, allow_private=allow_private,
        allowed_hosts=allowed_hosts)
    out = {"version": CONTENT_PROBE_VERSION, "endpoint": endpoint,
           "session_established": bool(session.get("established")),
           "inspected": {}, "reasons": [], "findings": []}
    if not out["session_established"]:
        out["reasons"].append(
            "session not established: %s" % session.get("reason"))
        return out
    sid = session.get("session_id")
    for n, (method, key) in enumerate(LISTS, start=1):
        payload = {"jsonrpc": "2.0", "id": 200 + n, "method": method}
        try:
            status, hdrs, raw = mcp_session._post_jsonrpc(
                endpoint, payload, token, session_id=sid,
                allow_private=allow_private, allowed_hosts=allowed_hosts)
        except Exception as exc:
            out["reasons"].append("%s: %s" % (method, exc))
            continue
        msg = _parse(status, hdrs, raw)
        res = msg.get("result") if isinstance(msg, dict) else None
        items = res.get(key) if isinstance(res, dict) else None
        if not isinstance(items, list):
            out["reasons"].append("%s: no result.%s" % (method, key))
            continue
        out["inspected"][key] = len(items)
        out["findings"].extend(_scan(endpoint, key, items))
    return out
