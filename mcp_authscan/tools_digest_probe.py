import json
from urllib.request import Request

from mcp_authscan.defpin import tools_digest
from mcp_authscan.oauth_probes_v2 import (
    OAUTH_PROBE_VERSION,
    EgressRefusalError,
    _egress_guard,
)


def _capture_tools_digest(endpoint, token, extra_headers=None):
    """Digest of the tools/list payload a live session returned. Provenance, not a verdict."""
    hdrs = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer %s" % token,
        "User-Agent": "mcp-authscan/%s" % OAUTH_PROBE_VERSION,
    }
    for k, v in (extra_headers or {}).items():
        if v:
            hdrs[k] = v
    has_session = any(k.lower() == "mcp-session-id" for k in hdrs)
    body = json.dumps({"jsonrpc": "2.0", "id": "digest", "method": "tools/list", "params": {}}).encode("utf-8")
    req = Request(endpoint, data=body, headers=hdrs, method="POST")
    try:
        status, resp_headers, raw = _egress_guard(req)
        if not (200 <= int(status) < 300):
            return {"digest": None, "reason": "tools/list returned status %s" % status}
        text = raw.decode("utf-8", "replace")
        ctype = resp_headers.get("Content-Type") or ""
        if "text/event-stream" in ctype:
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
