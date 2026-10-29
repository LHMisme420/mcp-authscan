"""An acquired token that was not revoked is reported like an unrevoked client (PROBE_CONTRACT.md [4]).

token-cors [4] with --acquire-token: when a token's revocation is not a 2xx (5xx, 401 asking for
client authentication, a failed request) or no revocation_endpoint is advertised, the scanner
prints `[!] TOKEN STILL LIVE: ...` to stderr, the text report carries
`Token Status: STILL LIVE on the server (...)` and the JSON `token_still_live: true`.
`Token Status: revoked` / `none acquired` otherwise. The token value never appears.
Local fixture only (fixture_oauth.py TOKEN_REVOCATION=fail|auth|ok, REVOCATION=fail|auth|absent).
"""
import json
import socket

import pytest

from mcp_authscan import oauth_probes_v2 as probes
from tests.test_probes_pkce_redirect import fixture
from tests.test_token_cors_acquired import _cli, _no_secret, _state, scope  # noqa: F401 (autouse)

BOTH = "access_token, refresh_token"


def _entries(js_stdout):
    """client_registration entries from --json output, wherever the payload nests them."""
    found = []

    def walk(o):
        if isinstance(o, dict):
            if "client_registration" in o and isinstance(o["client_registration"], list):
                found.extend(o["client_registration"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    start = js_stdout.index("{")
    walk(json.JSONDecoder().raw_decode(js_stdout[start:])[0])
    return found


def _no_token(base, runs):
    """No fixture token, code, RAT or pasted address in any byte any run wrote."""
    for p, pasted, _ in runs:
        _no_secret(p.stdout, p.stderr)
        if pasted:
            assert pasted not in p.stdout and pasted not in p.stderr


@pytest.mark.parametrize("env, result, client_live", [
    ({"TOKEN_REVOCATION": "fail"}, "access_token revocation not confirmed (HTTP 503 error=temporarily_unavailable); "
                                   "refresh_token revocation not confirmed (HTTP 503 error=temporarily_unavailable)",
     False),
    ({"TOKEN_REVOCATION": "auth"}, "access_token revocation not confirmed (HTTP 401 error=invalid_client); "
                                   "refresh_token revocation not confirmed (HTTP 401 error=invalid_client)", False),
    ({"TOKEN_REVOCATION": "fail", "REVOCATION": "auth"},
     "access_token revocation not confirmed (HTTP 503 error=temporarily_unavailable); "
     "refresh_token revocation not confirmed (HTTP 503 error=temporarily_unavailable)", True),
    ({"REVOCATION": "absent"}, "not attempted: no revocation_endpoint advertised", True),
])
def test_unrevoked_token_is_reported_still_live(env, result, client_live):
    with fixture(**env) as base:
        runs = [_cli(base, "--acquire-token", *fmt) for fmt in ((), ("--json",), ("--html",), ("--sarif",))]
        st = _state(base)
    text, js = runs[0][0], runs[1][0]
    for p, _, prompts in runs:
        assert prompts == 1 and p.returncode in (0, 1), p.stderr[-500:]
        assert ("[!] token revocation not confirmed: %s issued by %s to client_id " % (BOTH, base)) in p.stderr
        assert " (%s); revoke on the server" % result in p.stderr
        assert "STILL LIVE" not in p.stdout + p.stderr
    assert st["tokens_outstanding"] == 8   # 4 runs x (access + refresh), none revoked
    assert ("Token Status: revocation not confirmed for %s (%s). Revoke on the server."
            % (BOTH, result)) in text.stdout
    # client_live: since probe set 2026.11.02 the client never goes to /revoke, so whatever
    # REVOCATION says, its removal is out of scope (no registration_client_uri)
    assert ("Client Removal: client removal is out of scope for this tool: client_id dcr-client-1 registered at "
            "%s by this run was not removed" % base) in text.stdout
    entry = _entries(js.stdout)[0]
    assert entry["token_revocation_unconfirmed"] is True and entry["token_revocation"] == result
    assert entry["token_types_unconfirmed"] == ["access_token", "refresh_token"]
    _no_token(base, runs)


def test_token_revoked_while_client_still_live():
    """TOKEN_REVOCATION=ok, REVOCATION=fail: token and client results are independent."""
    with fixture(TOKEN_REVOCATION="ok", REVOCATION="fail") as base:
        runs = [_cli(base, "--acquire-token"), _cli(base, "--acquire-token", "--json")]
        st = _state(base)
    text, js = runs[0][0], runs[1][0]
    assert st["tokens_outstanding"] == 0
    assert "Token Status: revoked" in text.stdout
    assert "token revocation not confirmed" not in text.stdout + text.stderr
    assert "[!] client removal is out of scope for this tool: client_id dcr-client-1" in text.stderr
    assert "Client Removal: client removal is out of scope for this tool: client_id dcr-client-1" in text.stdout
    entry = _entries(js.stdout)[0]
    assert entry["token_revocation_unconfirmed"] is False and entry["client_deleted"] is False
    _no_token(base, runs)


def test_token_revoked():
    with fixture() as base:
        runs = [_cli(base, "--acquire-token"), _cli(base, "--acquire-token", "--json")]
        st = _state(base)
    text, js = runs[0][0], runs[1][0]
    assert st["tokens_outstanding"] == 0
    assert "Token Status: revoked" in text.stdout
    assert "STILL LIVE" not in text.stdout + text.stderr
    entry = _entries(js.stdout)[0]
    assert entry["token_revocation_unconfirmed"] is False
    assert entry["token_revocation"] == "access_token HTTP 200; refresh_token HTTP 200"
    _no_token(base, runs)


@pytest.mark.parametrize("extra", [(), ("--acquire-token",)])
def test_no_token_acquired(extra):
    """Plain scan, or an attended scan where the person pastes nothing: no token to revoke."""
    with fixture() as base:
        runs = [_cli(base, *extra, paste_mode="empty"), _cli(base, *extra, "--json", paste_mode="empty")]
    text, js = runs[0][0], runs[1][0]
    assert "Token Status: none acquired" in text.stdout
    assert "token revocation not confirmed" not in text.stdout + text.stderr
    entry = _entries(js.stdout)[0]
    assert entry["token_revocation_unconfirmed"] is None and entry["token_revocation"] is None
    _no_token(base, runs)


def test_token_revocation_request_exception_is_not_revoked():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = "http://127.0.0.1:%d/revoke" % s.getsockname()[1]
    client = probes._Client("dcr-client-x", "http://localhost/mcp-authscan/callback", "registered")
    tokens = [("access_token", "fixture-acquired-token-x"), ("refresh_token", "fixture-acquired-refresh-x")]
    not_revoked, result = probes._revoke_tokens({"revocation_endpoint": dead}, client, tokens)
    assert not_revoked == ["access_token", "refresh_token"]
    assert result.startswith("access_token revocation not confirmed (request failed: ")
    assert "refresh_token revocation not confirmed (request failed: " in result
    assert "fixture-acquired" not in result
