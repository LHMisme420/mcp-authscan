import hashlib
import json
import sys

from mcp_authscan.resource_probes import ProbeRecord, _egress_guard_fetch

PRE = "a token whose scopes omit the scope the invoked tool requires"


def _h(hs, n):
    for k in (hs or {}):
        if k.lower() == n:
            return hs.get(k) or ""
    return ""


def run(u, tok, tool, under):
    p = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
    h = {"Authorization": "Bearer " + tok, "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    try:
        s, hs, b = _egress_guard_fetch(u, p, headers=h)
    except Exception as e:
        return ProbeRecord("scope_enforcement", "scope_enforcement", "NOT_OBSERVED", detail="No response: " + str(e)[:80], endpoint=u, prerequisites=[PRE], prerequisite_met=False, limitation="Request did not complete")
    b = b or b""
    c = _h(hs, "www-authenticate")
    base = dict(http_status=s, headers_observed={"WWW-Authenticate": c or "absent"}, body_sha256=hashlib.sha256(b).hexdigest(), endpoint=u, prerequisites=[PRE], prerequisite_met=True)

    def rec(o, d, sev=None, lim=None):
        return ProbeRecord("scope_enforcement", "scope_enforcement", o, severity=sev, limitation=lim, detail=d, **base)

    if not isinstance(s, int) or s // 100 == 5:
        return rec("NOT_OBSERVED", "Server error " + str(s), lim="Server did not answer cleanly")
    if s == 403 and "insufficient_scope" in c:
        return rec("PASS", "Under-scoped token refused: " + c)
    if s == 401:
        return rec("PASS", "Token refused outright")
    if s == 403:
        return rec("NOT_OBSERVED", "403 without normative challenge", lim="Refusal not readable as a scope decision")
    if s == 200:
        if not under:
            return rec("NOT_OBSERVED", "200 with no declared shortfall", lim="Token scope not established as insufficient for this tool")
        try:
            r = json.loads(b)
        except ValueError:
            r = {}
        if isinstance(r, dict) and "result" in r:
            return rec("FAIL", "Caller without the required scope invoked " + tool, sev="HIGH")
        return rec("NOT_OBSERVED", "200 with no result body", lim="Tool result not confirmed")
    return rec("NOT_OBSERVED", "Unexpected status " + str(s), lim="Not a scope signal")


if len(sys.argv) > 3:
    us = len(sys.argv) > 4 and sys.argv[4] == "under"
    o = run(sys.argv[1], sys.argv[2], sys.argv[3], us)
    try:
        from dataclasses import asdict
        print(json.dumps(asdict(o), default=str))
    except Exception:
        print(json.dumps(dict(vars(o)), default=str))
