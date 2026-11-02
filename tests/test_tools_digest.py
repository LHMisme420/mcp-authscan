import json
from mcp_authscan import tools_digest_probe as o
from mcp_authscan.defpin import canonical_tools, tools_digest

TOOLS = [
    {"name": "b", "description": "second", "inputSchema": {"type": "object"}},
    {"name": "a", "description": "first", "inputSchema": {"type": "object"}},
]

def _fake(body, seen):
    def guard(req, allow_private=False):
        seen.append(dict(req.header_items()))
        return 200, {}, json.dumps(body).encode()
    return guard

def test_digest_matches_canonical_digest(monkeypatch):
    seen = []
    monkeypatch.setattr(o, "_egress_guard", _fake({"result": {"tools": TOOLS}}, seen))
    got = o._capture_tools_digest("https://example.test/mcp", "tok", {"Mcp-Session-Id": "s1"})
    assert got["digest"] == tools_digest(TOOLS)
    assert got["tool_count"] == 2
    assert got["session_header"] is True
    assert any(k.lower() == "mcp-session-id" for h in seen for k in h)

def test_digest_is_order_independent(monkeypatch):
    monkeypatch.setattr(o, "_egress_guard", _fake({"result": {"tools": TOOLS}}, []))
    a = o._capture_tools_digest("https://example.test/mcp", "tok", {})["digest"]
    monkeypatch.setattr(o, "_egress_guard", _fake({"result": {"tools": list(reversed(TOOLS))}}, []))
    b = o._capture_tools_digest("https://example.test/mcp", "tok", {})["digest"]
    assert a == b

def test_missing_result_tools_records_reason(monkeypatch):
    monkeypatch.setattr(o, "_egress_guard", _fake({"result": {}}, []))
    got = o._capture_tools_digest("https://example.test/mcp", "tok", {})
    assert got["digest"] is None
    assert "reason" in got

def test_egress_refusal_propagates(monkeypatch):
    def boom(req, allow_private=False):
        raise o.EgressRefusalError("refused")
    monkeypatch.setattr(o, "_egress_guard", boom)
    try:
        o._capture_tools_digest("https://example.test/mcp", "tok", {})
    except o.EgressRefusalError:
        return
    raise AssertionError("refusal did not propagate")
