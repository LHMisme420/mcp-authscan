import json
from urllib.request import Request

from mcp_authscan import oauth_probes_v2
from mcp_authscan.defpin import tools_digest
from mcp_authscan.mcp_session import SESSION_HEADER, open_session
from mcp_authscan.oauth_probes_v2 import (
    OAUTH_PROBE_VERSION,
    EgressRefusalError,
    _egress_guard,
)

TOOLS_DIGEST = {}


def _capture_tools_digest(endpoint, token, extra_headers=None, allow_private=None):
    """Digest of the tools/list payload a live session returned. Provenance, not a verdict."""
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer %s" % token,
        "User-Agent": "mcp-authscan/%s" % OAUTH_PROBE_VERSION,
    }
    if not token:
        hdrs.pop("Authorization", None)
    for k, v in (extra_headers or {}).items():
        if v:
            hdrs[k] = v
    has_session = any(k.lower() == "mcp-session-id" for k in hdrs)
    body = json.dumps({"jsonrpc": "2.0", "id": "digest", "method": "tools/list", "params": {}}).encode("utf-8")
    req = Request(endpoint, data=body, headers=hdrs, method="POST")
    try:
        status, resp_headers, raw = _egress_guard(req, allow_private=allow_private)
        if not (200 <= int(status) < 300):
            return {"digest": None, "reason": "tools/list returned status %s" % status}
        text = raw.decode("utf-8", "replace")
        ctype = ""
        for key, value in resp_headers.items():
            if key.lower() == "content-type":
                ctype = value
                break
        if "text/event-stream" in (ctype or ""):
            text = "\n".join(
                line[5:].strip() for line in text.splitlines() if line.startswith("data:")
            )
        msg = json.loads(text)
        tools = msg.get("result", {}).get("tools") if isinstance(msg, dict) else None
        if not isinstance(tools, list):
            return {"digest": None, "reason": "tools/list response had no result.tools"}
        return {
            "digest": tools_digest(tools),
            "tool_count": len(tools),
            "session_header": has_session,
            "method": "tools/list",
        }
    except EgressRefusalError:
        raise
    except Exception as exc:
        return {"digest": None, "reason": "tools/list not obtained: %s" % exc}


def report_payload(target, token=None, allow_private=None):
    """Capture the digest for the scanned endpoint. No verdict, no coverage movement."""
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        return {"captured": False, "reason": "target is not an HTTP endpoint"}
    if allow_private is None:
        allow_private = oauth_probes_v2.ALLOW_PRIVATE_TARGETS
    session = open_session(target, token, allow_private=allow_private)
    if not session.get("established"):
        TOOLS_DIGEST.clear()
        TOOLS_DIGEST.update({
            "captured": False,
            "endpoint": target,
            "phase": "initialize",
            "reason": session.get("reason") or "session not established",
            "http_status": session.get("http_status"),
        })
        return dict(TOOLS_DIGEST)
    captured = _capture_tools_digest(target, token, {SESSION_HEADER: session["session_id"]},
                                     allow_private=allow_private)
    TOOLS_DIGEST.clear()
    TOOLS_DIGEST.update({
        "captured": captured.get("digest") is not None,
        "endpoint": target,
        "digest": captured.get("digest"),
        "tool_count": captured.get("tool_count"),
        "session_established": True,
        "protocol_version": session.get("protocol_version"),
        "server_name": session.get("server_name"),
        "server_version": session.get("server_version"),
    })
    if captured.get("reason"):
        TOOLS_DIGEST["reason"] = captured["reason"]
    return dict(TOOLS_DIGEST)
