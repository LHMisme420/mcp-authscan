import json
import hashlib
from mcp_authscan.oauth_probes_v2 import ProbeRecord
from mcp_authscan.mcp_session import open_session, _post_jsonrpc

PROBE_ID = "resources-read-session"


def _excluded(endpoint, why):
    return ProbeRecord(probe_id=PROBE_ID, name=PROBE_ID, status="EXCLUDED",
                       detail=why, endpoint=endpoint)


def _body_json(raw):
    try:
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except (ValueError, UnicodeDecodeError):
        return None


def _err_code(data):
    if not isinstance(data, dict):
        return None
    e = data.get("error")
    return e.get("code") if isinstance(e, dict) else None


def probe_resources_read(target_url, token, allow_private=None, allowed_hosts=None):
    if not token:
        return _excluded(target_url, "Prerequisite missing: no authenticated session, resources/read not attempted")
    session = open_session(target_url, token, allow_private=allow_private, allowed_hosts=allowed_hosts)
    if not session.get("established"):
        return _excluded(target_url, "Prerequisite missing: initialize did not establish a session (%s)" % session.get("reason"))
    sid = session["session_id"]
    listed = {"jsonrpc": "2.0", "method": "resources/list", "params": {}, "id": 2}
    status, headers, raw = _post_jsonrpc(target_url, listed, token, session_id=sid,
                                         allow_private=allow_private, allowed_hosts=allowed_hosts)
    if status // 100 == 5:
        return _excluded(target_url, "resources/list returned server error %s, cannot assess" % status)
    data = _body_json(raw)
    result = data.get("result") if isinstance(data, dict) else None
    resources = result.get("resources") if isinstance(result, dict) else None
    if not isinstance(resources, list) or not resources:
        return _excluded(target_url, "Prerequisite missing: resources/list returned no resources to read")
    uri = resources[0].get("uri") if isinstance(resources[0], dict) else None
    if not uri:
        return _excluded(target_url, "Prerequisite missing: first listed resource carries no uri")
    forged = "00000000-0000-4000-8000-000000000000"
    payload = {"jsonrpc": "2.0", "method": "resources/read", "params": {"uri": uri}, "id": 3}
    status2, headers2, raw2 = _post_jsonrpc(target_url, payload, token, session_id=forged,
                                           allow_private=allow_private, allowed_hosts=allowed_hosts)
    if status2 // 100 == 5:
        return _excluded(target_url, "resources/read returned server error %s, cannot assess" % status2)
    sha = hashlib.sha256(raw2).hexdigest()
    if status2 in (401, 403):
        return ProbeRecord(probe_id=PROBE_ID, name=PROBE_ID, status="PASS", http_status=status2,
                           body_sha256=sha, detail="resources/read refused a session id the server did not issue",
                           endpoint=target_url)
    data2 = _body_json(raw2)
    if _err_code(data2) == -32601:
        return _excluded(target_url, "Prerequisite missing: server does not implement resources/read, JSON-RPC error -32601 method not found")
    result2 = data2.get("result") if isinstance(data2, dict) else None
    contents = result2.get("contents") if isinstance(result2, dict) else None
    if isinstance(contents, list) and contents:
        return ProbeRecord(probe_id=PROBE_ID, name=PROBE_ID, status="FAIL", http_status=status2,
                           body_sha256=sha, severity="HIGH",
                           detail="resources/read returned resource content for a session id the server did not issue; severity_basis: read of resource content demonstrated, no write or execute observed",
                           endpoint=target_url)
    return ProbeRecord(probe_id=PROBE_ID, name=PROBE_ID, status="NOT_OBSERVED", http_status=status2,
                       body_sha256=sha, detail="resources/read response showed neither resource content nor a refusal",
                       endpoint=target_url)
