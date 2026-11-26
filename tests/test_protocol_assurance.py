import json

import pytest

from mcp_authscan import mcp_session, content_probe


ENDPOINT = "https://example.invalid/mcp"


def response(result=None, request_id=1):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": result,
    }


def valid_initialize():
    return response({
        "protocolVersion": mcp_session.PROTOCOL_VERSION,
        "capabilities": {},
        "serverInfo": {
            "name": "controlled-fixture",
            "version": "1.0",
        },
    })


def http(msg, status=200):
    return (
        status,
        {"Content-Type": "application/json"},
        json.dumps(msg).encode(),
    )


@pytest.mark.parametrize("msg", [
    {},
    [],
    {"jsonrpc": "2.0", "id": 1,
     "error": {"code": -32600, "message": "Invalid"}},
    response({}),
    response({"capabilities": {}}),
    response({}, request_id=99),
    response({}, request_id=True),
    response({}, request_id=1.0),
])
def test_invalid_initialize_never_establishes(monkeypatch, msg):
    calls = []

    def post(endpoint, payload, token, **kwargs):
        calls.append(payload["method"])
        return http(msg)

    monkeypatch.setattr(mcp_session, "_post_jsonrpc", post)

    result = mcp_session.open_session(ENDPOINT, None)

    assert result["established"] is False
    assert calls == ["initialize"]


def test_valid_initialize_establishes(monkeypatch):
    def post(endpoint, payload, token, **kwargs):
        if payload["method"] == "initialize":
            return http(valid_initialize())
        return 202, {}, b""

    monkeypatch.setattr(mcp_session, "_post_jsonrpc", post)

    result = mcp_session.open_session(ENDPOINT, None)
    assert result["established"] is True


@pytest.mark.parametrize("status", [401, 403, 500])
def test_failed_notification_blocks_session(monkeypatch, status):
    def post(endpoint, payload, token, **kwargs):
        if payload["method"] == "initialize":
            return http(valid_initialize())
        return status, {}, b""

    monkeypatch.setattr(mcp_session, "_post_jsonrpc", post)

    result = mcp_session.open_session(ENDPOINT, None)
    assert result["established"] is False


@pytest.mark.parametrize("status,mode", [
    (401, "valid"),
    (403, "valid"),
    (500, "valid"),
    (200, "wrong-id"),
    (200, "error"),
    (200, "wrong-version"),
    (200, "malformed-items"),
])
def test_invalid_list_never_recorded(monkeypatch, status, mode):
    monkeypatch.setattr(
        mcp_session, "open_session",
        lambda *a, **k: {
            "established": True,
            "session_id": "fixture",
        }
    )

    def post(endpoint, payload, token, **kwargs):
        key = payload["method"].split("/")[0]
        msg = response({key: []}, payload["id"])

        if mode == "wrong-id":
            msg["id"] = 999
        elif mode == "error":
            msg["error"] = {"code": -32600}
        elif mode == "wrong-version":
            msg["jsonrpc"] = "1.0"
        elif mode == "malformed-items":
            msg["result"][key] = [123]

        return http(msg, status)

    monkeypatch.setattr(mcp_session, "_post_jsonrpc", post)

    result = content_probe.observe(ENDPOINT)
    assert result["operations"] == ["initialize"]


def test_valid_empty_lists_are_observed(monkeypatch):
    monkeypatch.setattr(
        mcp_session, "open_session",
        lambda *a, **k: {
            "established": True,
            "session_id": "fixture",
        }
    )

    def post(endpoint, payload, token, **kwargs):
        key = payload["method"].split("/")[0]
        return http(response({key: []}, payload["id"]))

    monkeypatch.setattr(mcp_session, "_post_jsonrpc", post)

    result = content_probe.observe(ENDPOINT)

    assert result["operations"] == [
        "initialize",
        "tools/list",
        "prompts/list",
        "resources/list",
    ]
