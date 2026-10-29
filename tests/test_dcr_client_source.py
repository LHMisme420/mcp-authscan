"""Client source for probes 7 and 8 (PROBE_CONTRACT.md, probe set 2026.10.30).

Order: dynamic client registration (RFC 7591) at the advertised registration_endpoint with the
scanner's loopback redirect, else MCPAUTHSCAN_CLIENT_ID/MCPAUTHSCAN_REDIRECT_URI, else EXCLUDED.
A registered client is revoked at the advertised revocation_endpoint before anything is reported.
Fixture branches: REGISTRATION=fail, REVOCATION=fail, defaults succeed. Local fixture only.
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

R = "http://127.0.0.1/mcp-authscan/callback"


@pytest.fixture(autouse=True)
def scope(monkeypatch):
    monkeypatch.setattr(monolith, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(probes, "ALLOW_PRIVATE_TARGETS", True, raising=False)
    monkeypatch.setattr(monolith, "ALLOWED_HOSTS", {"127.0.0.1"})
    for k in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
        monkeypatch.delenv(k, raising=False)
    del probes.CLIENT_REPORTS[:]


def _clients(base):
    with urlopen(base + "/_clients", timeout=5) as r:
        return json.loads(r.read())


def _assess(base):
    records, _ = probes.run_oauth_assessment(base, None, base + "/mcp")
    by_name = {r.name: r for r in records}
    return by_name, probes.CLIENT_REPORTS[-1]


def _no_registration_secret(by_name, report):
    blob = json.dumps([r.as_dict() for r in by_name.values()]) + json.dumps(report)
    assert "fixture-rat" not in blob


def test_registration_ok_client_used_and_revoked():
    with fixture() as base:
        by_name, report = _assess(base)
        clients = _clients(base)
        assert _hits(base) == {}
    assert by_name["pkce-s256"].status == "PASS", by_name["pkce-s256"].detail
    assert by_name["redirect-uri-exact"].status == "PASS", by_name["redirect-uri-exact"].detail
    assert report["client_registered"] is True
    assert report["client_source"] == "registered"
    assert report["redirect_uri"] == R
    assert report["registration"].startswith("HTTP 201, client_id dcr-client-")
    assert report["revocation"] == "HTTP 200"
    # the fixture saw the revocation, with the registration_access_token as the token
    assert clients["registered"] == []
    assert clients["revoked"] == [{"client_id": report["client_id"], "token_sent": True}]
    _no_registration_secret(by_name, report)


def test_registration_fail_without_env_is_excluded_with_reason():
    with fixture(REGISTRATION="fail") as base:
        by_name, report = _assess(base)
    reason = "Dynamic client registration unavailable: registration returned HTTP 400 error=invalid_client_metadata"
    p7, p8 = by_name["pkce-s256"], by_name["redirect-uri-exact"]
    assert p7.status == "EXCLUDED" and p7.limitation == \
        "No client_id to build an authorization request (MCPAUTHSCAN_CLIENT_ID not set)"
    assert p8.status == "EXCLUDED" and p8.limitation == "No registered redirect_uri to compare against"
    assert p7.detail == reason and p8.detail == reason
    assert report["client_registered"] is False and report["client_source"] == "none"
    assert report["revocation"] == "not applicable: no client was registered"


def test_registration_fail_falls_back_to_env(monkeypatch):
    with fixture(REGISTRATION="fail") as base:
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")
        by_name, report = _assess(base)
        assert _hits(base) == {}
    assert by_name["pkce-s256"].status == "PASS"
    assert by_name["redirect-uri-exact"].status == "PASS"
    assert report["client_source"] == "environment (MCPAUTHSCAN_CLIENT_ID)"
    assert report["client_id"] == "fixture-client" and report["redirect_uri"] == base + "/cb"


def test_registration_preferred_over_env(monkeypatch):
    with fixture() as base:
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")
        by_name, report = _assess(base)
    assert report["client_source"] == "registered" and report["redirect_uri"] == R


def test_revocation_fail_is_reported_and_verdicts_stand():
    with fixture(REVOCATION="fail") as base:
        by_name, report = _assess(base)
        clients = _clients(base)
    assert by_name["pkce-s256"].status == "PASS" and by_name["redirect-uri-exact"].status == "PASS"
    assert report["client_registered"] is True
    assert report["revocation"] == "HTTP 503 error=temporarily_unavailable"
    assert clients["registered"] == [report["client_id"]] and clients["revoked"] == []
    _no_registration_secret(by_name, report)


def test_registered_client_detects_prefix_redirect_match():
    with fixture(REDIRECT_MATCH="prefix") as base:
        by_name, report = _assess(base)
        assert _hits(base) == {}
    r = by_name["redirect-uri-exact"]
    assert r.status == "FAIL" and r.severity == "CRITICAL", r.detail
    assert report["client_source"] == "registered"


def _cli(base, *extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    proc = subprocess.run(
        [sys.executable, "-c", "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())",
         base + "/mcp", "--allow-private", "--authorized-by", "X", "--auth-basis", "x",
         "--contact", "x@x.com", *extra],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
    return proc


@pytest.mark.parametrize("env,registered,revocation", [
    ({}, "yes", "HTTP 200"),
    ({"REGISTRATION": "fail"}, "no", "not applicable: no client was registered"),
    ({"REVOCATION": "fail"}, "yes", "HTTP 503 error=temporarily_unavailable"),
])
def test_report_states_registration_redirect_and_revocation(env, registered, revocation):
    with fixture(**env) as base:
        text = _cli(base)
        js = _cli(base, "--json")
    assert "CLIENT REGISTRATION" in text.stdout
    assert "Client Registered: %s" % registered in text.stdout
    assert "Revocation: %s" % revocation in text.stdout
    assert "Redirect URI Used: %s" % (R if registered == "yes" else "(none)") in text.stdout
    entry = json.loads(js.stdout)["client_registration"][0]
    assert entry["revocation"] == revocation
    for out in (text.stdout, text.stderr, js.stdout, js.stderr):
        assert "fixture-rat" not in out
