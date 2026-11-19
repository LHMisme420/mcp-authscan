"""Probe set 2026.11.19.1: the credential-grant probes cannot produce a false clean.

From a18ad02 (2026-11-11) token-cors [4] and password-grant [6] sent the client this run had just
registered, even when the operator supplied MCPAUTHSCAN_CLIENT_ID. A server that issues
client_credentials and password-grant tokens only to its own client answered invalid_request,
token-cors went NOT_OBSERVED, password-grant graded PASS on that 400, and the scan said
VERDICT PASS with zero findings. These tests pin the fix.
"""
import json
import os
import subprocess
import sys

from mcp_authscan import oauth_probes_v2
from tests.test_probes_pkce_redirect import ROOT, fixture


def _scan_json(base, tmp_path, env_client=True):
    env = {**os.environ}
    for k in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
        env.pop(k, None)
    if env_client:
        env.update(MCPAUTHSCAN_CLIENT_ID="fixture-client", MCPAUTHSCAN_CLIENT_SECRET="fixture-secret",
                   MCPAUTHSCAN_REDIRECT_URI=base + "/cb")
    out = tmp_path / "report.json"
    p = subprocess.run(
        [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
         base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x",
         "--contact", "scanner-test@example.invalid", "--json", "--output", str(out)],
        cwd=str(tmp_path), env=env, capture_output=True, text=True, timeout=120)
    return p, json.loads(out.read_text())


def _by_name(report):
    return {r["name"]: r for r in report["probes"]}


def test_operator_client_is_used_and_misbehaviour_is_found(tmp_path):
    with fixture(MISBEHAVE="1") as base:
        p, report = _scan_json(base, tmp_path)
    probes = _by_name(report)
    assert probes["token-cors"]["status"] == "FAIL", probes["token-cors"]
    assert probes["password-grant"]["status"] == "FAIL", probes["password-grant"]
    assert report["findings_count"] >= 2
    assert p.returncode == 1, p.stderr
    # The fixture also accepts dynamic registration, so both clients exist; the report says which
    # one the credential-grant probes used.
    clients = report["client_registration"]
    assert [c["client_registered"] for c in clients] == [True]
    assert [c["credential_grant_client_source"] for c in clients] == ["environment (MCPAUTHSCAN_CLIENT_ID)"]


def test_password_grant_invalid_request_is_not_a_pass(monkeypatch):
    monkeypatch.setattr(oauth_probes_v2, "_pace", lambda: None)
    monkeypatch.setattr(oauth_probes_v2, "_egress_guard",
                        lambda req, allow_private=False: (400, {}, b'{"error": "invalid_request"}'))
    r = oauth_probes_v2.probe_password_grant("http://127.0.0.1:1/token")
    assert r.status == "NOT_OBSERVED", r
    assert "unsupported_grant_type" in (r.detail or "")


def test_password_grant_unsupported_grant_type_is_a_pass(monkeypatch):
    monkeypatch.setattr(oauth_probes_v2, "_pace", lambda: None)
    monkeypatch.setattr(oauth_probes_v2, "_egress_guard",
                        lambda req, allow_private=False: (400, {}, b'{"error": "unsupported_grant_type"}'))
    assert oauth_probes_v2.probe_password_grant("http://127.0.0.1:1/token").status == "PASS"
