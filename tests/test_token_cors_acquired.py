"""token-cors [4] acquired-token mode (--acquire-token), PROBE_CONTRACT.md [4], probe set 2026.10.30.

Local fixture only (fixture_oauth.py): TOKEN_CORS=none|wildcard|wildcard-cred|echo,
CONSENT=deny|interactive, REGISTRATION=fail, REVOCATION=fail. Every test also checks the
token never leaves memory: it is revoked at the fixture, and no scanner output, record,
exception string or report contains it.
"""
import json
import os
import subprocess
import sys
from urllib.request import urlopen

import pytest

import mcp_authscan.monolith as monolith
from mcp_authscan import oauth_probes_v2 as probes
from tests.test_probes_pkce_redirect import ROOT, fixture, _hits

SECRETS = ("fixture-acquired", "fixture-code", "fixture-rat", "fixture-secret")


@pytest.fixture(autouse=True)
def scope(monkeypatch):
    monkeypatch.setattr(monolith, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(probes, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(monolith, "ALLOWED_HOSTS", {"127.0.0.1"})
    for k in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
        monkeypatch.delenv(k, raising=False)
    del probes.CLIENT_REPORTS[:]


@pytest.fixture
def acquire(monkeypatch):
    monkeypatch.setattr(probes, "ACQUIRE_TOKEN", True)


@pytest.fixture
def authorize_calls(monkeypatch):
    calls = []
    real = probes._authorize

    def counting(endpoint, params):
        calls.append(dict(params))
        return real(endpoint, params)
    monkeypatch.setattr(probes, "_authorize", counting)
    return calls


def _state(base):
    with urlopen(base + "/_clients", timeout=5) as r:
        return json.loads(r.read())


def _token_cors(base):
    records, _ = probes.run_oauth_assessment(base, None, base + "/mcp")
    return next(r for r in records if r.name == "token-cors")


def _no_secret(*texts):
    for t in texts:
        for s in SECRETS:
            assert s not in t, s


def _clean(r):
    _no_secret(json.dumps(r.as_dict()), repr(r.as_dict()))


@pytest.mark.parametrize("cors,status,severity", [
    ("none", "PASS", None),
    ("wildcard", "FAIL", "HIGH"),
    ("wildcard-cred", "FAIL", "CRITICAL"),
    ("echo", "NOT_OBSERVED", None),
])
def test_cors_variants(acquire, cors, status, severity):
    with fixture(TOKEN_CORS=cors) as base:
        r = _token_cors(base)
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == status and r.severity == severity, r.detail
    assert r.http_status == 200
    assert "access token obtained" in r.detail
    assert "revocation: access_token HTTP 200; refresh_token HTTP 200" in r.detail
    assert st["tokens_issued"] == 2 and st["tokens_revoked"] == 2 and st["tokens_outstanding"] == 0
    assert '"access_token": "[redacted]"' in r.body_excerpt
    if status == "FAIL":
        assert r.endpoint == base + "/token"
    _clean(r)


def test_consent_refused(acquire, authorize_calls):
    with fixture(CONSENT="deny") as base:
        r = probes.probe_token_cors(base + "/token", metadata={
            "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token",
            "revocation_endpoint": base + "/revoke"}, client=_registered(base))
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == "NOT_OBSERVED"
    assert "authorization refused: error=access_denied; no token obtained" in r.detail
    assert len(authorize_calls) == 1
    assert st["tokens_issued"] == 0
    _clean(r)


def test_interactive_consent_is_named_limitation_without_retry(acquire, authorize_calls):
    with fixture(CONSENT="interactive") as base:
        r = probes.probe_token_cors(base + "/token", metadata={
            "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token"},
            client=_registered(base))
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == "NOT_OBSERVED"
    assert r.limitation == "Consent requires human interaction, cannot complete unattended"
    assert "Consent requires human interaction, cannot complete unattended" in r.detail
    assert "did not submit consent or retry" in r.detail
    assert len(authorize_calls) == 1          # one request, no loop, no retry
    assert st["tokens_issued"] == 0


def test_interactive_consent_in_full_assessment(acquire):
    with fixture(CONSENT="interactive") as base:
        r = _token_cors(base)
    assert r.status == "NOT_OBSERVED" and r.limitation == probes.CONSENT_LIMITATION


def _registered(base):
    """Register a client at the fixture the way run_oauth_assessment does."""
    client, reason = probes._register_client({"authorization_endpoint": base + "/authorize",
                                              "registration_endpoint": base + "/register"})
    assert client is not None and client.usable, reason
    return client


def test_env_client_when_registration_fails(acquire, monkeypatch):
    with fixture(REGISTRATION="fail", TOKEN_CORS="wildcard") as base:
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_SECRET", "fixture-secret")
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")
        r = _token_cors(base)
        st = _state(base)
        assert _hits(base) == {}
    assert r.status == "FAIL" and r.severity == "HIGH", r.detail
    assert "client fixture-client (environment (MCPAUTHSCAN_CLIENT_ID))" in r.detail
    assert st["tokens_outstanding"] == 0
    _clean(r)


def test_excluded_without_any_client(acquire):
    with fixture(REGISTRATION="fail") as base:
        r = _token_cors(base)
        st = _state(base)
    assert r.status == "EXCLUDED"
    assert r.limitation.startswith("No client to obtain a token")
    assert r.detail == ("Dynamic client registration unavailable: "
                        "registration returned HTTP 400 error=invalid_client_metadata")
    assert st["tokens_issued"] == 0


def test_revocation_failure_reported_verdict_stands(acquire):
    with fixture(REVOCATION="fail") as base:
        r = _token_cors(base)
    assert r.status == "PASS", r.detail
    assert "revocation: access_token HTTP 503 error=temporarily_unavailable" in r.detail
    _clean(r)


def test_exception_strings_are_sanitized(acquire, monkeypatch):
    real = probes._egress_guard

    def boom(req, *a, **kw):
        if req.full_url.endswith("/token"):
            raise RuntimeError("leaked " + req.data.decode())
        return real(req, *a, **kw)
    monkeypatch.setattr(probes, "_egress_guard", boom)
    with fixture() as base:
        r = _token_cors(base)
    assert r.status == "NOT_OBSERVED"
    assert r.detail.endswith("token request failed: RuntimeError")
    assert "code_verifier" not in json.dumps(r.as_dict())
    _clean(r)


def test_off_by_default(authorize_calls):
    assert probes.ACQUIRE_TOKEN is False
    with fixture(TOKEN_CORS="wildcard-cred") as base:
        r = probes.probe_token_cors(base + "/token", metadata={
            "authorization_endpoint": base + "/authorize", "token_endpoint": base + "/token"},
            client=_registered(base))
        st = _state(base)
    assert authorize_calls == [] and st["tokens_issued"] == 0
    assert "Acquired-token mode" not in (r.detail or "")


def _cli(base, *extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    return subprocess.run(
        [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
         base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x",
         "--contact", "x@x.com", *extra],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)


def test_help_lists_acquire_token():
    proc = subprocess.run([sys.executable, "-c",
                           "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())", "--help"],
                          cwd=str(ROOT), capture_output=True, text=True, timeout=30)
    assert "--acquire-token" in proc.stdout


@pytest.mark.parametrize("env", [{}, {"TOKEN_CORS": "wildcard"}, {"TOKEN_CORS": "wildcard-cred"},
                                 {"TOKEN_CORS": "echo"}, {"CONSENT": "deny"}, {"CONSENT": "interactive"},
                                 {"REVOCATION": "fail"}])
def test_token_absent_from_all_cli_output(env):
    """grep every byte the CLI writes (text, --json, --sarif, --html) for the fixture's token."""
    with fixture(**env) as base:
        runs = [_cli(base, "--acquire-token", *fmt) for fmt in ((), ("--json",), ("--sarif",), ("--html",))]
        st = _state(base)
        assert _hits(base) == {}
    for p in runs:
        assert p.returncode in (0, 1), p.stderr[-500:]
        _no_secret(p.stdout, p.stderr)
    # REVOCATION=fail: the fixture refuses revocation, so its tokens stay outstanding there
    assert st["tokens_outstanding"] == (8 if env == {"REVOCATION": "fail"} else 0)
    if not env or "TOKEN_CORS" in env:
        assert st["tokens_issued"] == 8   # 4 runs x (access + refresh), all revoked
