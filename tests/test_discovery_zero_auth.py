"""Discovery on an unchallenged 200 must not grade zero-auth when metadata exists."""
import json
from contextlib import nullcontext
from types import SimpleNamespace

from mcp_authscan import monolith as m


BODY = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"serverInfo": {"name": "x"}}}).encode()


def _fake_200(monkeypatch, payload=BODY):
    resp = SimpleNamespace(status=200, read=lambda n=-1: payload)
    monkeypatch.setattr(m, "urlopen", lambda *a, **k: nullcontext(resp))


def test_metadata_on_200_is_not_zero_auth(monkeypatch):
    _fake_200(monkeypatch)
    endpoints = {"token": "https://example.test/token", "authorize": "https://example.test/authorize"}
    info = {"method": "RFC 9728 derived", "authorization_servers": ["https://example.test"]}
    monkeypatch.setattr(m, "_derived_resource_metadata", lambda *a, **k: (endpoints, info))

    eps, disc = m.discover_oauth_endpoints("https://example.test/mcp", allowed_hosts={"example.test"})

    assert eps == endpoints
    assert disc.get("status") != "ZERO_AUTH_DETECTED"


def test_no_metadata_on_200_still_zero_auth(monkeypatch):
    _fake_200(monkeypatch)
    monkeypatch.setattr(m, "_derived_resource_metadata", lambda *a, **k: (None, None))

    eps, info = m.discover_oauth_endpoints("https://example.test/mcp", allowed_hosts={"example.test"})

    assert eps is None
    assert info.get("status") == "ZERO_AUTH_DETECTED"
