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


def _post_jsonrpc(endpoint, payload, token, session_id=None, allow_private=None,
                   allowed_hosts=None):
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer %s" % token,
        "User-Agent": "mcp-authscan/%s" % OAUTH_PROBE_VERSION,
    }
    if not token:
        hdrs.pop("Authorization", None)
    if session_id:
        hdrs[SESSION_HEADER] = session_id
    req = Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers=hdrs, method="POST")
    return _egress_guard(req, allow_private=allow_private, allowed_hosts=allowed_hosts)


def _rpc_result(msg, request_id):
    """Return a matching successful JSON-RPC result, or None."""
    if not isinstance(msg, dict):
        return None
    if msg.get("jsonrpc") != "2.0":
        return None
    if type(msg.get("id")) is not type(request_id):
        return None
    if msg.get("id") != request_id or "error" in msg:
        return None
    result = msg.get("result")
    return result if isinstance(result, dict) else None


def open_session(endpoint, token, allow_private=None, allowed_hosts=None):
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
        status, headers, raw = _post_jsonrpc(endpoint, init, token, allow_private=allow_private, allowed_hosts=allowed_hosts)
    except EgressRefusalError:
        raise
    except Exception as exc:
        return {"established": False, "reason": "initialize not obtained: %s" % exc}
    if not (200 <= int(status) < 300):
        return {"established": False, "http_status": status,
                "reason": "initialize returned HTTP %s" % status}
    session_id = _header(headers, SESSION_HEADER)
    try:
        msg = _parse_body(raw, _header(headers, "Content-Type"))
    except Exception as exc:
        return {"established": False, "http_status": status,
                "reason": "initialize body unreadable: %s" % exc}
    result = _rpc_result(msg, init["id"])
    server = result.get("serverInfo") if result is not None else None

    if (
        result is None
        or not isinstance(result.get("protocolVersion"), str)
        or not result["protocolVersion"]
        or not isinstance(result.get("capabilities"), dict)
        or not isinstance(server, dict)
        or not isinstance(server.get("name"), str)
        or not server["name"]
        or not isinstance(server.get("version"), str)
        or not server["version"]
    ):
        return {
            "established": False,
            "http_status": status,
            "reason": "invalid MCP initialize result",
        }

    if result["protocolVersion"] != PROTOCOL_VERSION:
        return {
            "established": False,
            "http_status": status,
            "reason": "unsupported negotiated protocol version",
        }

    note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    try:
        nstatus, _, _ = _post_jsonrpc(endpoint, note, token, session_id=session_id,
                                      allow_private=allow_private, allowed_hosts=allowed_hosts)
    except EgressRefusalError:
        raise
    except Exception:
        nstatus = None
    if nstatus is None or not (200 <= int(nstatus) < 300):
        return {
            "established": False,
            "http_status": status,
            "notify_status": nstatus,
            "reason": "initialized notification not accepted",
        }
    return {
        "established": True,
        "session_id": session_id,
        "http_status": status,
        "notify_status": nstatus,
        "protocol_version": result.get("protocolVersion"),
        "server_name": server.get("name"),
        "server_version": server.get("version"),
    }
