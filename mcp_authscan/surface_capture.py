"""Capture a live MCP server surface, one JSON-RPC call at a time."""
import json
from urllib.request import Request

from .tools_digest_probe import EgressRefusalError, OAUTH_PROBE_VERSION, _egress_guard

SSE_PREFIX = "data:"
PROTOCOL_VERSION = "2025-06-18"


def build_headers(token=None, session_id=None, extra_headers=None):
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "mcp-authscan/%s" % OAUTH_PROBE_VERSION,
    }
    if token:
        hdrs["Authorization"] = "Bearer %s" % token
    if session_id:
        hdrs["Mcp-Session-Id"] = session_id
    for key, value in (extra_headers or {}).items():
        if value:
            hdrs[key] = value
    return hdrs


def header_value(resp_headers, wanted):
    for key, value in (resp_headers or {}).items():
        if key.lower() == wanted:
            return value
    return ""


def decode_body(raw, resp_headers):
    text = raw.decode("utf-8", "replace")
    if "text/event-stream" in (header_value(resp_headers, "content-type") or ""):
        text = chr(10).join(line[5:].strip() for line in text.splitlines() if line.startswith(SSE_PREFIX))
    return text


def call_method(endpoint, method, params=None, token=None, session_id=None, allow_private=None, allowed_hosts=None):
    payload = {"jsonrpc": "2.0", "id": method, "method": method}
    if params is not None:
        payload["params"] = params
    req = Request(endpoint, data=json.dumps(payload).encode("utf-8"), headers=build_headers(token, session_id), method="POST")
    try:
        status, resp_headers, raw = _egress_guard(req, allow_private=allow_private, allowed_hosts=allowed_hosts)
    except EgressRefusalError:
        raise
    except (TypeError, AttributeError, NameError):
        raise
    except Exception as exc:
        return None, session_id, "%s not obtained: %s" % (method, exc)
    new_session = header_value(resp_headers, "mcp-session-id") or session_id
    if not (200 <= int(status) < 300):
        return None, new_session, "%s returned status %s" % (method, status)
    try:
        msg = json.loads(decode_body(raw, resp_headers))
    except ValueError as exc:
        return None, new_session, "%s response was not JSON: %s" % (method, exc)
    if not isinstance(msg, dict):
        return None, new_session, "%s response was not an object" % method
    if "error" in msg:
        return None, new_session, "%s returned a JSON-RPC error" % method
    return msg.get("result"), new_session, None

def capture_surface(endpoint, token=None, allow_private=None, allowed_hosts=None):
    from .surface import surface_digest

    reasons = []
    init_params = {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "mcp-authscan", "version": OAUTH_PROBE_VERSION},
    }
    init, session_id, reason = call_method(endpoint, "initialize", init_params, token=token, allow_private=allow_private, allowed_hosts=allowed_hosts)
    if reason:
        reasons.append(reason)
    instructions = init.get("instructions") if isinstance(init, dict) else None
    surface = {"instructions": instructions or "", "tools": [], "prompts": [], "resources": []}
    captured = set()
    for key, method in (("tools", "tools/list"), ("prompts", "prompts/list"), ("resources", "resources/list")):
        result, session_id, reason = call_method(endpoint, method, {}, token=token, session_id=session_id, allow_private=allow_private, allowed_hosts=allowed_hosts)
        if reason:
            reasons.append(reason)
            continue
        items = result.get(key) if isinstance(result, dict) else None
        if not isinstance(items, list):
            reasons.append("%s had no result.%s" % (method, key))
            continue
        surface[key] = items
        captured.add(key)
    digest = surface_digest(surface) if "tools" in captured else None
    return {"surface": surface, "digest": digest, "captured": sorted(captured), "reasons": reasons}
