import json

from mcp_authscan import mcp_session as m
from mcp_authscan.oauth_probes_v2 import EgressRefusalError

INIT_RESULT = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "serverInfo": {"name": "stub", "version": "9.9.9"},
    },
}


def _fake(init_headers=None, init_status=200, init_body=None, ctype="application/json", calls=None):
    calls = calls if calls is not None else []

    def guard(req, timeout=5, allow_private=None, allowed_hosts=None, follow_redirects=True):
        body = json.loads(req.data.decode("utf-8"))
        calls.append((body.get("method"), {k.lower(): v for k, v in req.header_items()}))
        if body.get("method") == "initialize":
            payload = init_body if init_body is not None else json.dumps(INIT_RESULT)
            headers = {"Content-Type": ctype}
            headers.update(init_headers or {})
            return init_status, headers, payload.encode("utf-8")
        return 202, {}, b""

    return guard, calls


def test_session_established_and_notification_carries_id(monkeypatch):
    guard, calls = _fake(init_headers={"Mcp-Session-Id": "s1"})
    monkeypatch.setattr(m, "_egress_guard", guard)
    got = m.open_session("https://example.test/mcp", "tok")
    assert got["established"] is True
    assert got["session_id"] == "s1"
    assert got["server_name"] == "stub"
    assert got["protocol_version"] == "2025-06-18"
    assert got["notify_status"] == 202
    init_call, note_call = calls[0], calls[1]
    assert "mcp-session-id" not in init_call[1]
    assert note_call[1]["mcp-session-id"] == "s1"




def test_non_2xx_reports_status(monkeypatch):
    guard, _ = _fake(init_headers={"Mcp-Session-Id": "s1"}, init_status=401)
    monkeypatch.setattr(m, "_egress_guard", guard)
    got = m.open_session("https://example.test/mcp", "tok")
    assert got["established"] is False
    assert got["http_status"] == 401


def test_sse_body_is_parsed(monkeypatch):
    guard, _ = _fake(init_headers={"Mcp-Session-Id": "s1"}, ctype="text/event-stream",
                     init_body="event: message\ndata: " + json.dumps(INIT_RESULT))
    monkeypatch.setattr(m, "_egress_guard", guard)
    got = m.open_session("https://example.test/mcp", "tok")
    assert got["established"] is True
    assert got["server_name"] == "stub"


def test_egress_refusal_propagates(monkeypatch):
    def boom(req, timeout=5, allow_private=None, allowed_hosts=None, follow_redirects=True):
        raise EgressRefusalError("refused")

    monkeypatch.setattr(m, "_egress_guard", boom)
    try:
        m.open_session("https://example.test/mcp", "tok")
    except EgressRefusalError:
        return
    raise AssertionError("refusal did not propagate")
def test_missing_session_header_still_establishes(monkeypatch):
    guard, _ = _fake()
    monkeypatch.setattr(m, "_egress_guard", guard)
    got = m.open_session("https://example.test/mcp", "tok")
    assert got["established"] is True
