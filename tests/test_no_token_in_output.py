"""No credential a server returns is ever recorded or printed (default mode, no --acquire-token).

fixture_oauth.py with MISBEHAVE=1 issues fixture-token (client_credentials) and
fixture-password-token (password grant) to the env client; neither may appear in any output.
"""
import os
import subprocess
import sys

from mcp_authscan._common import record, redact_secrets
from tests.test_probes_pkce_redirect import ROOT, fixture

TOKENS = ("fixture-token", "fixture-password-token", "fixture-secret")


def test_redact_secrets_json_and_form():
    assert redact_secrets(b'{"access_token": "abc", "n": {"refresh_token": "def"}, "token_type": "Bearer"}') == \
        b'{"access_token": "[redacted]", "n": {"refresh_token": "[redacted]"}, "token_type": "Bearer"}'
    assert redact_secrets(b'access_token=abc&token_type=Bearer') == b'access_token=[redacted]&token_type=Bearer'
    assert redact_secrets(b'<p>"id_token": "xyz"</p>') == b'<p>"id_token": "[redacted]"</p>'
    assert redact_secrets(b"") == b""


def test_record_never_stores_token():
    r = record(probe_id=6, name="password-grant", status="FAIL", http_status=200,
               body=b'{"access_token": "fixture-password-token"}', severity="HIGH", endpoint="http://x/token")
    assert "fixture-password-token" not in r.body_excerpt and "[redacted]" in r.body_excerpt


def test_default_scan_of_token_issuing_server_prints_no_token():
    with fixture(MISBEHAVE="1") as base:
        env = {**os.environ, "MCPAUTHSCAN_CLIENT_ID": "fixture-client",
               "MCPAUTHSCAN_CLIENT_SECRET": "fixture-secret", "MCPAUTHSCAN_REDIRECT_URI": base + "/cb"}
        outs = []
        for fmt in ((), ("--json",), ("--sarif",), ("--html",)):
            p = subprocess.run(
                [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
                 base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x",
                 "--contact", "x@x.com", *fmt], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
            outs.append(p)
    assert outs[0].returncode == 1          # the misbehaving fixture still has findings
    assert "token-cors" in outs[0].stdout and "password-grant" in outs[0].stdout
    for p in outs:
        for t in TOKENS:
            assert t not in p.stdout and t not in p.stderr, t
