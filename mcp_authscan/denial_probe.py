import os

from mcp_authscan import mcp_session
from mcp_authscan.oauth_probes_v2 import record

PROBE_ID = 13
PROBE_NAME = "denial-shape"
PROBE_CLASS = "mcp"


def credentials():
    return (os.environ.get("MCPAUTHSCAN_TOKEN") or None,
            os.environ.get("MCPAUTHSCAN_TOKEN_UNAUTH") or None)


def _post(endpoint, payload, token, session_id, allow_private, allowed_hosts):
    try:
        status, hdrs, raw = mcp_session._post_jsonrpc(
            endpoint, payload, token, session_id=session_id,
            allow_private=allow_private, allowed_hosts=allowed_hosts)
    except Exception as exc:
        return None, None, str(exc)
    try:
        msg = mcp_session._parse_body(raw, mcp_session._header(hdrs, "Content-Type"))
    except Exception as exc:
        return status, None, "body unreadable: %s" % exc
    return status, msg, None


def first_tool(endpoint, token, allow_private=None, allowed_hosts=None):
    session = mcp_session.open_session(
        endpoint, token, allow_private=allow_private, allowed_hosts=allowed_hosts)
    if not session.get("established"):
        return None, session.get("reason") or "session not established"
    status, msg, err = _post(endpoint, {"jsonrpc": "2.0", "id": 300, "method": "tools/list"},
                             token, session.get("session_id"), allow_private, allowed_hosts)
    if err:
        return None, "tools/list: %s" % err
    result = msg.get("result") if isinstance(msg, dict) else None
    tools = result.get("tools") if isinstance(result, dict) else None
    if not isinstance(tools, list):
        return None, "tools/list returned no tools"
    for tool in tools:
        if isinstance(tool, dict) and tool.get("name"):
            return tool["name"], None
    return None, "no named tool in tools/list"


def call_tool(endpoint, token, tool, allow_private=None, allowed_hosts=None, arguments=None):
    session = mcp_session.open_session(
        endpoint, token, allow_private=allow_private, allowed_hosts=allowed_hosts)
    if not session.get("established"):
        return session.get("http_status"), None, session.get("reason") or "session not established"
    payload = {"jsonrpc": "2.0", "id": 301, "method": "tools/call",
               "params": {"name": tool, "arguments": arguments or {}}}
    return _post(endpoint, payload, token, session.get("session_id"), allow_private, allowed_hosts)


def call_as(endpoint, token, tool=None, arguments=None, allow_private=None, allowed_hosts=None):
    session = mcp_session.open_session(
        endpoint, token, allow_private=allow_private, allowed_hosts=allowed_hosts)
    sid = session.get("session_id") if session.get("established") else None
    name = tool
    if name is None and sid:
        status, msg, err = _post(endpoint, {"jsonrpc": "2.0", "id": 300, "method": "tools/list"},
                                 token, sid, allow_private, allowed_hosts)
        result = msg.get("result") if isinstance(msg, dict) else None
        tools = result.get("tools") if isinstance(result, dict) else None
        if isinstance(tools, list):
            for item in tools:
                if isinstance(item, dict) and item.get("name"):
                    name = item["name"]
                    break
    if name is None:
        name = "get_record"
    payload = {"jsonrpc": "2.0", "id": 301, "method": "tools/call",
               "params": {"name": name, "arguments": arguments or {}}}
    return _post(endpoint, payload, token, sid, allow_private, allowed_hosts)
