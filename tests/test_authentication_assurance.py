import json

import pytest

from mcp_authscan import authentication_assurance as a

TARGET = "https://example.invalid/mcp"
TOKEN = "authorized-test-credential"

VALID = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "serverInfo": {
            "name": "fixture",
            "version": "1.0",
        },
    },
}


def response(status, body=None):
    return (
        status,
        {"Content-Type": "application/json"},
        json.dumps(body if body is not None else VALID).encode(),
    )


@pytest.mark.parametrize(
    "statuses,expected",
    [
        ([200, 401, 401, 200], "VERIFIED"),
        ([200, 403, 403, 200], "VERIFIED"),
        ([200, 401, 403, 200], "VERIFIED"),
        ([200, 200, 401, 200], "CONTRADICTED"),
        ([200, 401, 200, 200], "CONTRADICTED"),
        ([200, 200, 200, 200], "CONTRADICTED"),
        ([401, 401, 401, 200], "NOT_OBSERVED"),
        ([200, 401, 401, 401], "NOT_OBSERVED"),
        ([200, 404, 401, 200], "NOT_OBSERVED"),
        ([200, 405, 401, 200], "NOT_OBSERVED"),
        ([200, 500, 401, 200], "NOT_OBSERVED"),
        ([200, 429, 401, 200], "NOT_OBSERVED"),
        ([200, 302, 401, 200], "NOT_OBSERVED"),
    ],
)
def test_contrast(monkeypatch, statuses, expected):
    pending = iter(statuses)

    def guard(req, **kwargs):
        return response(next(pending))

    monkeypatch.setattr(a.mcp_session, "_egress_guard", guard)

    evidence = a.observe(TARGET, TOKEN)

    assert a.derive_verdict(evidence) == expected


def test_transport_and_credential_confidentiality(monkeypatch):
    calls = []

    def guard(req, **kwargs):
        headers = {
            k.lower(): v
            for k, v in req.header_items()
        }

        calls.append(headers)

        assert req.full_url == TARGET
        assert req.get_method() == "POST"
        assert kwargs["follow_redirects"] is False
        assert "mcp-session-id" not in headers

        payload = json.loads(req.data)

        assert payload["method"] == "initialize"
        assert payload["jsonrpc"] == "2.0"

        return response(
            200 if len(calls) in (1, 4) else 401
        )

    monkeypatch.setattr(a.mcp_session, "_egress_guard", guard)

    evidence = a.observe(TARGET, TOKEN)

    assert len(calls) == 4
    assert calls[0]["authorization"] == "Bearer " + TOKEN
    assert "authorization" not in calls[1]
    assert calls[2]["authorization"] != calls[0]["authorization"]
    assert calls[3]["authorization"] == calls[0]["authorization"]

    serialized = json.dumps(evidence)

    assert TOKEN not in serialized
    assert calls[2]["authorization"] not in serialized
    assert a.derive_verdict(evidence) == "VERIFIED"


def test_missing_token_never_contacts_target(monkeypatch):
    def guard(*args, **kwargs):
        pytest.fail("Unexpected network request")

    monkeypatch.setattr(a.mcp_session, "_egress_guard", guard)

    assert a.derive_verdict(
        a.observe(TARGET)
    ) == "NOT_OBSERVED"


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"result": {}},
        {"jsonrpc": "2.0", "id": 2, "result": VALID["result"]},
        {"jsonrpc": "2.0", "id": True, "result": VALID["result"]},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32603}},
        {"jsonrpc": "2.0", "id": 1, "result": []},
    ],
)
def test_invalid_protocol_cannot_verify(monkeypatch, body):
    def guard(req, **kwargs):
        return response(200, body)

    monkeypatch.setattr(a.mcp_session, "_egress_guard", guard)

    assert a.derive_verdict(
        a.observe(TARGET, TOKEN)
    ) == "NOT_OBSERVED"


def test_transport_exception_does_not_leak_token(monkeypatch):
    def guard(req, **kwargs):
        raise RuntimeError(TOKEN)

    monkeypatch.setattr(a.mcp_session, "_egress_guard", guard)

    evidence = a.observe(TARGET, TOKEN)

    assert TOKEN not in json.dumps(evidence)
    assert a.derive_verdict(evidence) == "NOT_OBSERVED"


def test_egress_refusal_propagates(monkeypatch):
    def guard(req, **kwargs):
        raise a.mcp_session.EgressRefusalError("refused")

    monkeypatch.setattr(a.mcp_session, "_egress_guard", guard)

    with pytest.raises(a.mcp_session.EgressRefusalError):
        a.observe(TARGET, TOKEN)


@pytest.mark.parametrize(
    "evidence",
    [
        None,
        {},
        {"version": "unknown"},
        {"verdict": "VERIFIED"},
        {"observations": []},
    ],
)
def test_incomplete_evidence_cannot_verify(evidence):
    assert a.derive_verdict(evidence) == "NOT_OBSERVED"


@pytest.mark.parametrize("changed", [
    "serverInfo",
    "capabilities",
    "protocolVersion",
])
def test_moving_baseline_cannot_verify(monkeypatch, changed):
    import copy

    altered = copy.deepcopy(VALID)

    replacements = {
        "serverInfo": {
            "name": "different-server",
            "version": "2.0",
        },
        "capabilities": {"tools": {}},
        "protocolVersion": "2025-03-26",
    }

    altered["result"][changed] = replacements[changed]

    replies = iter([
        response(200),
        response(401),
        response(401),
        response(200, altered),
    ])

    monkeypatch.setattr(
        a.mcp_session,
        "_egress_guard",
        lambda *args, **kwargs: next(replies),
    )

    evidence = a.observe(TARGET, TOKEN)

    assert a.derive_verdict(evidence) == "NOT_OBSERVED"


def test_missing_baseline_digest_cannot_verify(monkeypatch):
    statuses = iter([200, 401, 401, 200])

    monkeypatch.setattr(
        a.mcp_session,
        "_egress_guard",
        lambda *args, **kwargs: response(next(statuses)),
    )

    evidence = a.observe(TARGET, TOKEN)
    assert a.derive_verdict(evidence) == "VERIFIED"

    del evidence["observations"][0]["baseline_digest"]

    assert a.derive_verdict(evidence) == "NOT_OBSERVED"
