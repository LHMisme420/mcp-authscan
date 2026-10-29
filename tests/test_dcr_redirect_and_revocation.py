"""Ordered redirect candidates and the STILL LIVE report (PROBE_CONTRACT.md "Client source").

Fixture branches: REDIRECT_HOSTS=localhost | 127.0.0.1 | none; REVOCATION=fail (503),
REVOCATION=auth (401), REVOCATION=absent (no revocation_endpoint); a revocation request that
raises. Local fixture only.
"""
import json
import socket

import pytest

from mcp_authscan import oauth_probes_v2 as probes
from tests.test_dcr_client_source import _assess, _clients, _cli, scope  # noqa: F401 (autouse fixture)
from tests.test_probes_pkce_redirect import fixture

LOCALHOST, LOOPBACK4, LOOPBACK6 = (
    "http://localhost/mcp-authscan/callback",
    "http://127.0.0.1/mcp-authscan/callback",
    "http://[::1]/mcp-authscan/callback",
)
REFUSED = ('refused, HTTP 400 error=invalid_redirect_uri'
           ' error_description="redirect URI host is not on the allow-list"')


def test_candidates_are_one_ordered_constant_localhost_first():
    assert probes.REDIRECT_CANDIDATES == (LOCALHOST, LOOPBACK4, LOOPBACK6)


@pytest.mark.parametrize("hosts,tried,used", [
    (None, [(LOCALHOST, "accepted, HTTP 201")], LOCALHOST),
    ("localhost", [(LOCALHOST, "accepted, HTTP 201")], LOCALHOST),
    ("127.0.0.1", [(LOCALHOST, REFUSED), (LOOPBACK4, "accepted, HTTP 201")], LOOPBACK4),
])
def test_registration_walks_candidates_in_order(hosts, tried, used):
    with fixture(**({"REDIRECT_HOSTS": hosts} if hosts else {})) as base:
        by_name, report = _assess(base)
    assert [(t["redirect_uri"], t["result"]) for t in report["redirect_candidates_tried"]] == tried
    assert report["client_source"] == "registered" and report["redirect_uri"] == used
    assert by_name["pkce-s256"].status == "PASS" and by_name["redirect-uri-exact"].status == "PASS"
    assert report["client_still_live"] is False


def test_no_candidate_accepted_falls_back_to_env_then_excluded(monkeypatch):
    with fixture(REDIRECT_HOSTS="none") as base:
        by_name, report = _assess(base)
        monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", "fixture-client")
        monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", base + "/cb")
        env_by_name, env_report = _assess(base)
    assert [t["redirect_uri"] for t in report["redirect_candidates_tried"]] == [LOCALHOST, LOOPBACK4, LOOPBACK6]
    assert all(t["result"] == REFUSED for t in report["redirect_candidates_tried"])
    assert report["registration"] == ("registration refused every redirect candidate: HTTP 400 error=invalid_redirect_uri"
                                      ' error_description="redirect URI host is not on the allow-list"')
    assert report["client_registered"] is False and report["client_still_live"] is None
    for name in ("pkce-s256", "redirect-uri-exact"):
        assert by_name[name].status == "EXCLUDED"
        assert "Dynamic client registration unavailable: registration refused every redirect candidate" in by_name[name].detail
        assert env_by_name[name].status == "PASS"
    assert env_report["client_source"] == "environment (MCPAUTHSCAN_CLIENT_ID)"


def test_non_redirect_refusal_does_not_try_next_candidate():
    with fixture(REGISTRATION="fail") as base:
        _, report = _assess(base)
    assert [(t["redirect_uri"], t["result"]) for t in report["redirect_candidates_tried"]] == \
        [(LOCALHOST, 'refused, HTTP 400 error=invalid_client_metadata error_description="registration disabled on this fixture"')]


@pytest.mark.parametrize("env,revocation", [
    ({"REVOCATION": "fail"}, "HTTP 503 error=temporarily_unavailable"),
    ({"REVOCATION": "auth"}, "HTTP 401 error=invalid_client"),
    ({"REVOCATION": "absent"}, "not attempted: no revocation_endpoint advertised"),
])
def test_unrevoked_client_is_still_live_in_terminal_text_and_json(env, revocation):
    with fixture(**env) as base:
        text = _cli(base)
        js = _cli(base, "--json")
        clients = _clients(base)
    entry = json.loads(js.stdout)["client_registration"][0]
    assert entry["client_still_live"] is True and entry["revocation"] == revocation
    # each scan registered its own client; both are still registered at the fixture
    text_cid, js_cid = "dcr-client-1", entry["registered_client_id"]
    assert js_cid == "dcr-client-2" and clients["registered"] == [text_cid, js_cid]
    for proc, cid in ((text, text_cid), (js, js_cid)):
        assert "[!] CLIENT STILL LIVE: client_id %s registered at %s was not revoked (%s)" % (cid, base, revocation) \
            in proc.stderr
        assert proc.returncode == 0          # exit code unchanged by a failed revocation
    assert "Client Status: STILL LIVE on the server (registered client_id %s" % text_cid in text.stdout
    for out in (text.stdout, text.stderr, js.stdout, js.stderr):
        assert "fixture-rat" not in out and "registration_access_token\": \"fixture" not in out


def test_revocation_request_exception_is_still_live(capsys):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = "http://127.0.0.1:%d/revoke" % s.getsockname()[1]
    with fixture() as base:
        client = probes._Client("dcr-client-x", LOCALHOST, "registered", registration_access_token="fixture-rat-x")
        revoked, result = probes._revoke_client({"revocation_endpoint": dead}, client)
    assert revoked is False and result.startswith("request failed: ")
    assert client.registration_access_token is None
    assert "fixture-rat" not in result


def test_revoked_client_is_not_reported_live():
    with fixture() as base:
        text = _cli(base)
    assert "Client Status: revoked" in text.stdout
    assert "STILL LIVE" not in text.stdout + text.stderr
