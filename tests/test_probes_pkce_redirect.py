"""Fixture pairs for probe 7 (pkce-s256) and probe 8 (redirect-uri-exact).

Each probe must PASS on the secure fixture and FAIL on the misconfigured one
(PKCE_PLAIN=accept, REDIRECT_MATCH=prefix). Every run also checks that the
fixture never received a request for a returned Location (GET /_hits stays {}).
Ports are chosen dynamically so the tests do not collide with fixed-port suites.
"""
import json
import os
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.request import urlopen

import pytest

import mcp_authscan.monolith as monolith
from mcp_authscan import oauth_probes_v2 as probes

ROOT = Path(__file__).resolve().parents[1]


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def fixture(**env):
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "fixture_oauth.py")],
        env={**os.environ, "PORT": str(port), **env},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError("fixture exited early")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError("fixture did not start")
        yield "http://127.0.0.1:%d" % port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _hits(base):
    with urlopen(base + "/_hits", timeout=5) as r:
        return json.loads(r.read())


@pytest.fixture(autouse=True)
def scope(monkeypatch):
    monkeypatch.setattr(monolith, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(monolith, "ALLOWED_HOSTS", {"127.0.0.1"})
    for k in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
        monkeypatch.delenv(k, raising=False)


def _creds(monkeypatch, base, client="fixture-client", redirect=True):
    monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", client)
    if redirect:
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")


def _meta(base):
    return {"authorization_endpoint": base + "/authorize"}


# ---- probe 7 -----------------------------------------------------------------

def test_pkce_pass_on_secure_fixture(monkeypatch):
    with fixture() as base:
        _creds(monkeypatch, base)
        r = probes.probe_pkce_s256(_meta(base))
        assert _hits(base) == {}
    assert r.status == "PASS", r.detail
    assert r.http_status == 400 and r.severity is None
    assert "A (no code_challenge): refused" in r.detail
    assert "B (S256): proceeded" in r.detail
    assert "C (plain): refused" in r.detail


def test_pkce_fail_when_plain_accepted(monkeypatch):
    with fixture(PKCE_PLAIN="accept") as base:
        _creds(monkeypatch, base)
        r = probes.probe_pkce_s256(_meta(base))
        assert _hits(base) == {}
    assert r.status == "FAIL" and r.severity == "HIGH", r.detail
    assert r.http_status == 302
    assert "C (plain): proceeded" in r.detail
    assert "Nothing was sent to the returned Location" in r.detail
    assert "fixture-code" not in r.detail
    assert r.headers_observed["location"].endswith("/cb?code=[redacted]")


def test_pkce_excluded_without_authorization_endpoint(monkeypatch):
    monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
    r = probes.probe_pkce_s256({})
    assert r.status == "EXCLUDED" and r.limitation == "No authorization endpoint"


def test_pkce_excluded_without_client_id():
    r = probes.probe_pkce_s256({"authorization_endpoint": "http://127.0.0.1:1/authorize"})
    assert r.status == "EXCLUDED"
    assert "client_id" in r.limitation


def test_pkce_not_observed_when_every_request_refused(monkeypatch):
    """A refusal for an unknown client is not a PKCE refusal: B is refused too, so no verdict."""
    with fixture() as base:
        _creds(monkeypatch, base, client="unregistered-client")
        r = probes.probe_pkce_s256(_meta(base))
        assert _hits(base) == {}
    assert r.status == "NOT_OBSERVED"
    assert "B (S256): refused" in r.detail and "C (plain)" not in r.detail


# ---- probe 8 -----------------------------------------------------------------

def test_redirect_pass_on_secure_fixture(monkeypatch):
    with fixture() as base:
        _creds(monkeypatch, base)
        r = probes.probe_redirect_uri_exact(_meta(base))
        assert _hits(base) == {}
    assert r.status == "PASS", r.detail
    assert r.http_status == 400 and r.severity is None
    assert "P (registered redirect_uri): proceeded" in r.detail
    assert "N (%s/cbx): refused" % base in r.detail


def test_redirect_fail_when_prefix_matched(monkeypatch):
    with fixture(REDIRECT_MATCH="prefix") as base:
        _creds(monkeypatch, base)
        r = probes.probe_redirect_uri_exact(_meta(base))
        assert _hits(base) == {}
    assert r.status == "FAIL" and r.severity == "CRITICAL", r.detail
    assert r.http_status == 302
    assert "Nothing was sent to the returned Location" in r.detail
    assert r.headers_observed["location"] == base + "/cbx?code=[redacted]"


def test_redirect_excluded_without_redirect_uri(monkeypatch):
    with fixture() as base:
        _creds(monkeypatch, base, redirect=False)
        r = probes.probe_redirect_uri_exact(_meta(base))
    assert r.status == "EXCLUDED"
    assert r.limitation == "No registered redirect_uri to compare against"


def test_redirect_excluded_without_client_id(monkeypatch):
    monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", "http://127.0.0.1:1/cb")
    r = probes.probe_redirect_uri_exact({"authorization_endpoint": "http://127.0.0.1:1/authorize"})
    assert r.status == "EXCLUDED"
    assert r.limitation == "No registered redirect_uri to compare against"


def test_redirect_not_observed_when_baseline_refused(monkeypatch):
    with fixture() as base:
        _creds(monkeypatch, base, client="unregistered-client")
        r = probes.probe_redirect_uri_exact(_meta(base))
        assert _hits(base) == {}
    assert r.status == "NOT_OBSERVED"
    assert r.detail.startswith("No baseline: the registered redirect_uri was refused")
    assert "error=invalid_request" in r.detail
    assert "N (" not in r.detail


# ---- classification ------------------------------------------------------------

AE = "https://as.example/authorize"
RU = "https://app.example/cb"


def _cls(status, headers=None, body=b"", sent=RU, registered=RU):
    return probes._classify((status, probes.Headers(headers or {}), body), AE, sent, registered)[0]


@pytest.mark.parametrize("status,headers,body,expected", [
    (200, {}, b"<html>consent</html>", "proceeded"),
    (302, {"Location": RU + "?code=abc"}, b"", "proceeded"),
    (302, {"Location": "/consent?x=1"}, b"", "proceeded"),
    (302, {"Location": RU + "?error=access_denied"}, b"", "refused"),
    (400, {}, b'{"error": "invalid_request"}', "refused"),
    (400, {}, b"bad request", "neither"),
    (401, {}, b"", "neither"),
    (500, {}, b'{"error": "server_error"}', "neither"),
    (302, {"Location": "https://elsewhere.example/login"}, b"", "neither"),
    (302, {}, b"", "neither"),
])
def test_classify(status, headers, body, expected):
    assert _cls(status, headers, body) == expected


def test_classify_substituted_registered_uri_is_not_acceptance():
    near = RU + "x"
    assert _cls(302, {"Location": RU + "?code=abc"}, sent=near) == "neither"
    assert _cls(302, {"Location": near + "?code=abc"}, sent=near) == "proceeded"


def test_location_redacted():
    assert probes._redact_location(RU + "?code=abc&state=s") == RU + "?code=[redacted]&state=s"
    assert probes._redact_location(RU + "#access_token=t") == RU + "#access_token=[redacted]"


def test_no_redirect_opener_does_not_follow():
    with fixture() as base:
        from urllib.request import Request
        req = Request(base + "/authorize?response_type=code&client_id=fixture-client"
                      "&code_challenge=" + probes._pkce_challenge() + "&code_challenge_method=S256")
        status, headers, _ = probes._egress_guard(req, allow_private=True, follow_redirects=False)
        assert status == 302 and headers.get("Location") == base + "/cb?code=fixture-code"
        assert _hits(base) == {}


def test_pkce_challenge_is_43_chars():
    assert len(probes._pkce_challenge()) == 43
