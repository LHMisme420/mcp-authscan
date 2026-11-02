import json
from urllib.request import Request

from mcp_authscan.oauth_probes_v2 import (
    OAUTH_PROBE_VERSION,
    EgressRefusalError,
    _egress_guard,
)

PROTOCOL_VERSION = "2025-06-18"
SESSION_HEADER = "Mcp-Session-Id"


def _header(headers, name):
    want = name.lower()
    try:
        items = headers.items()
    except Exception:
        return None
    for key, value in items:
        if key.lower() == want:
            return value
    return None


def _parse_body(raw, ctype):
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in (ctype or ""):
        text = "\n".join(
            line[5:].strip() for line in text.splitlines() if line.startswith("data:")
        )
    return json.loads(text)


def _post_jsonrpc(endpoint, payload, token, session_id=None, allow_private=None):
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer %s" % token,
        "User-Agent": "mcp-authscan/%s" % OAUTH_PROBE_VERSION,
    }
    if session_id:
        hdrs[SESSION_HEADER] = session_id
    req = Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers=hdrs, method="POST")
    return _egress_guard(req, allow_private=allow_private)


def open_session(endpoint, token, allow_private=None):
    """Initialize an MCP session and return what tools/list needs. Produces no verdict."""
    init = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp-authscan", "version": OAUTH_PROBE_VERSION},
        },
    }
    try:
        status, headers, raw = _post_jsonrpc(endpoint, init, token, allow_private=allow_private)
    except EgressRefusalError:
        raise
    except Exception as exc:
        return {"established": False, "reason": "initialize not obtained: %s" % exc}
    if not (200 <= int(status) < 300):
        return {"established": False, "http_status": status,
                "reason": "initialize returned HTTP %s" % status}
    session_id = _header(headers, SESSION_HEADER)
    if not session_id:
        return {"established": False, "http_status": status,
                "reason": "no Mcp-Session-Id in initialize response"}
    try:
        msg = _parse_body(raw, _header(headers, "Content-Type"))
    except Exception as exc:
        return {"established": False, "http_status": status,
                "reason": "initialize body unreadable: %s" % exc}
    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    try:
        nstatus, _, _ = _post_jsonrpc(endpoint, note, token, session_id=session_id,
                                      allow_private=allow_private)
    except EgressRefusalError:
        raise
    except Exception:
        nstatus = None
    result = msg.get("result") if isinstance(msg, dict) else None
    result = result if isinstance(result, dict) else {}
    server = result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else {}
    return {
        "established": True,
        "session_id": session_id,
        "http_status": status,
        "notify_status": nstatus,
        "protocol_version": result.get("protocolVersion"),
        "server_name": server.get("name"),
        "server_version": server.get("version"),
    }
