"""Token revocation and client removal, probe set 2026.11.02 (PROBE_CONTRACT.md "Revocation").

Tokens: RFC 7009 POST to revocation_endpoint with token, token_type_hint, client_id and
client_secret (empty for a public client). A non-2xx reads
`<hint> revocation not confirmed (HTTP <status> ...)`, never TOKEN STILL LIVE, and the exit code
is the same as when the token was revoked.
Clients: never sent to the RFC 7009 endpoint. RFC 7592 DELETE on registration_client_uri with
the registration_access_token as bearer only when the registration returned both; otherwise one
line, "client removal is out of scope for this tool", naming the client_id. A client from the
environment: exactly "no client was registered by this run", with no revocation wording.
Local fixture only (fixture_oauth.py REVOCATION=sdk, TOKEN_REVOCATION=ok|described,
CLIENT_DELETE=ok|fail, REGISTRATION=fail with MCPAUTHSCAN_CLIENT_ID).
"""
import json
import os
import re
import subprocess
import sys

from tests.test_dcr_client_source import _assess, _cli as _plain_cli, scope  # noqa: F401 (autouse)
from tests.test_probes_pkce_redirect import ROOT, fixture
from tests.test_token_cors_acquired import _cli, _no_secret, _state
from tests.test_token_still_live import _entries

OUT_OF_SCOPE = "client removal is out of scope for this tool: client_id %s registered at %s by this run was not removed"
ENV_CLIENT = "no client was registered by this run"
BANNED = ("revoked", "unrevoked", "revocable", "still live", "revocation time", "mcpauthscan_client_revoked_at")


def _block(stdout):
    """The CLIENT REGISTRATION block of a text report."""
    start = stdout.index("CLIENT REGISTRATION")
    return stdout[start:stdout.index("FINDINGS SUMMARY", start)]


def _no_client_token_posts(state):
    """No POST /revoke ever carried a registration_access_token (clients never go to RFC 7009)."""
    assert all(f["token"] != "registration_access_token" for f in state["revoke_forms"]), state["revoke_forms"]


def test_sdk_revocation_gets_every_field_and_client_is_out_of_scope():
    """REVOCATION=sdk requires client_secret; without it the server answers 400 'client_secret: Field required'."""
    with fixture(REVOCATION="sdk") as base:
        runs = [_cli(base, "--acquire-token"), _cli(base, "--acquire-token", "--json")]
        st = _state(base)
    text, js = runs[0][0], runs[1][0]
    assert st["tokens_outstanding"] == 0
    assert len(st["revoke_forms"]) == 4      # 2 runs x (access + refresh), nothing for the clients
    for f in st["revoke_forms"]:
        assert f["fields"] == ["client_id", "client_secret", "token", "token_type_hint"]
        assert f["client_secret"] == "empty" and f["token"] == "issued"
    _no_client_token_posts(st)
    assert sorted(st["registered"]) == ["dcr-client-1", "dcr-client-2"] and st["deleted"] == []
    entry = _entries(js.stdout)[0]
    assert entry["token_revocation"] == "access_token HTTP 200; refresh_token HTTP 200"
    assert entry["token_revocation_unconfirmed"] is False
    assert entry["client_removal"] == OUT_OF_SCOPE % ("dcr-client-2", base) and entry["client_deleted"] is False
    assert "Client Removal: %s\n" % (OUT_OF_SCOPE % ("dcr-client-1", base)) in text.stdout
    assert "Token Status: revoked" in text.stdout
    for p, _, _ in runs:
        lines = [l for l in p.stderr.splitlines() if "client removal is out of scope" in l]
        assert len(lines) == 1 and "refused" not in lines[0]
        assert "STILL LIVE" not in p.stdout + p.stderr and "Field required" not in p.stdout + p.stderr
        _no_secret(p.stdout, p.stderr)


def test_token_revocation_400_reads_not_confirmed_and_keeps_the_exit_code():
    with fixture(TOKEN_REVOCATION="described") as base:
        runs = [_cli(base, "--acquire-token"), _cli(base, "--acquire-token", "--json")]
        st = _state(base)
    with fixture(TOKEN_REVOCATION="ok") as base_ok:
        ok_runs = [_cli(base_ok, "--acquire-token"), _cli(base_ok, "--acquire-token", "--json")]
    text, js = runs[0][0], runs[1][0]
    nc = ('revocation not confirmed (HTTP 400 error=invalid_request '
          'error_description="token revocation is disabled on this fixture")')
    want = "access_token %s; refresh_token %s" % (nc, nc)
    assert st["tokens_outstanding"] == 4
    entry = _entries(js.stdout)[0]
    assert entry["token_revocation"] == want and entry["token_revocation_unconfirmed"] is True
    assert entry["token_types_unconfirmed"] == ["access_token", "refresh_token"]
    assert "Token Status: revocation not confirmed for access_token, refresh_token (%s). Revoke on the server." \
        % want in text.stdout
    for (p, _, _), (q, _, _) in zip(runs, ok_runs):
        assert "[!] token revocation not confirmed: access_token, refresh_token issued by %s to client_id " % base \
            in p.stderr
        assert "STILL LIVE" not in p.stdout + p.stderr
        assert p.returncode == q.returncode, (p.returncode, q.returncode)
        _no_secret(p.stdout, p.stderr)


def test_rfc7592_delete_when_advertised():
    with fixture(CLIENT_DELETE="ok") as base:
        text, js = _plain_cli(base), _plain_cli(base, "--json")
        st = _state(base)
    assert st["deleted"] == ["dcr-client-1", "dcr-client-2"] and st["registered"] == []
    assert st["revoke_forms"] == []
    entry = json.loads(js.stdout)["client_registration"][0]
    assert entry["client_removal"] == "deleted: client_id dcr-client-2, RFC 7592 DELETE HTTP 204"
    assert entry["client_deleted"] is True
    assert "Client Removal: deleted: client_id dcr-client-1, RFC 7592 DELETE HTTP 204\n" in text.stdout
    for p in (text, js):
        assert "out of scope" not in p.stdout + p.stderr and "STILL LIVE" not in p.stdout + p.stderr
        _no_secret(p.stdout, p.stderr)


def test_rfc7592_delete_failure_is_not_confirmed():
    with fixture(CLIENT_DELETE="fail") as base:
        text = _plain_cli(base)
        st = _state(base)
    want = ("client deletion not confirmed: client_id dcr-client-1, RFC 7592 DELETE HTTP 503 "
            "error=temporarily_unavailable; remove it on the server")
    assert st["registered"] == ["dcr-client-1"] and st["deleted"] == [] and st["revoke_forms"] == []
    assert "Client Removal: %s\n" % want in text.stdout
    assert "[!] %s" % want in text.stderr
    assert "STILL LIVE" not in text.stdout + text.stderr
    _no_secret(text.stdout, text.stderr)


def test_not_advertised_is_out_of_scope_and_never_posts_the_client():
    with fixture() as base:
        _, report = _assess(base)
        text = _plain_cli(base)
        st = _state(base)
    assert st["revoke_forms"] == [] and st["revoked"] == [] and st["deleted"] == []
    assert sorted(st["registered"]) == ["dcr-client-1", "dcr-client-2"]
    assert report["client_removal"] == OUT_OF_SCOPE % ("dcr-client-1", base)
    assert report["client_deleted"] is False
    lines = [l for l in text.stderr.splitlines() if "client removal is out of scope" in l]
    assert lines == ["[!] " + OUT_OF_SCOPE % ("dcr-client-2", base)]
    assert "Client Removal: %s\n" % (OUT_OF_SCOPE % ("dcr-client-2", base)) in text.stdout
    for t in (text.stdout, text.stderr):
        assert "refused" not in _block(text.stdout) and "STILL LIVE" not in t
    _no_secret(text.stdout, text.stderr)


def _env_cli(base, *extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    env.update(MCPAUTHSCAN_CLIENT_ID="fixture-client", MCPAUTHSCAN_REDIRECT_URI=base + "/cb")
    return subprocess.run(
        [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
         base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x",
         "--contact", "x@x.com", *extra],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)


def test_env_supplied_client_has_no_revocation_wording(monkeypatch):
    with fixture(REGISTRATION="fail") as base:
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")
        _, report = _assess(base)
        text, js = _env_cli(base), _env_cli(base, "--json")
        st = _state(base)
    assert st["revoke_forms"] == [] and st["deleted"] == []
    entry = json.loads(js.stdout)["client_registration"][0]
    for e in (report, entry):
        assert e["client_source"] == "environment (MCPAUTHSCAN_CLIENT_ID)" and e["client_id"] == "fixture-client"
        assert e["client_removal"] == ENV_CLIENT and e["client_deleted"] is None
    block = _block(text.stdout)
    assert "Client Removal: %s\n" % ENV_CLIENT in block
    for blob in (block, json.dumps(entry), json.dumps(report), text.stderr, js.stderr):
        low = blob.lower()
        for word in BANNED:
            assert word not in low, (word, blob)
    assert not re.search(r"\brevok", block.lower() + json.dumps(entry).lower())
