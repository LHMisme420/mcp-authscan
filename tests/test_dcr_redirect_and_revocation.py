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
    assert report["client_removal"] == ("client removal is out of scope for this tool: client_id %s registered "
                                        "at %s by this run was not removed" % (report["client_id"], base))


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
    assert report["client_registered"] is False and report["client_deleted"] is None
    assert report["client_removal"] == "no client was registered by this run"
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
    ({"REVOCATION": "fail"}, "client removal is out of scope for this tool"),
    ({"REVOCATION": "auth"}, "client removal is out of scope for this tool"),
    ({"REVOCATION": "absent"}, "client removal is out of scope for this tool"),
])
def test_unrevoked_client_is_still_live_in_terminal_text_and_json(env, revocation):
    # Since probe set 2026.11.02 a client never goes to the RFC 7009 endpoint, so its result does
    # not depend on REVOCATION: without registration_client_uri, removal is out of scope.
    with fixture(**env) as base:
        text = _cli(base)
        js = _cli(base, "--json")
        clients = _clients(base)
    entry = json.loads(js.stdout)["client_registration"][0]
    oos = revocation + ": client_id %s registered at %s by this run was not removed"
    assert entry["client_deleted"] is False and entry["client_removal"] == oos % ("dcr-client-2", base)
    # each scan registered its own client; both are still registered at the fixture
    text_cid, js_cid = "dcr-client-1", entry["registered_client_id"]
    assert js_cid == "dcr-client-2" and clients["registered"] == [text_cid, js_cid]
    assert clients["revoke_forms"] == []
    for proc, cid in ((text, text_cid), (js, js_cid)):
        assert [l for l in proc.stderr.splitlines() if revocation in l] == ["[!] " + oos % (cid, base)]
        assert proc.returncode == 0          # exit code unchanged by a client left registered
    assert "Client Removal: %s\n" % (oos % (text_cid, base)) in text.stdout
    for out in (text.stdout, text.stderr, js.stdout, js.stderr):
        assert "fixture-rat" not in out and "registration_access_token\": \"fixture" not in out


def test_revocation_request_exception_is_still_live(capsys):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = "http://127.0.0.1:%d/register/dcr-client-x" % s.getsockname()[1]
    with fixture() as base:
        client = probes._Client("dcr-client-x", LOCALHOST, "registered", registration_access_token="fixture-rat-x",
                                registration_client_uri=dead)
        revoked, result = probes._remove_client(base, client)
    assert revoked is False
    assert result.startswith("client deletion not confirmed: client_id dcr-client-x, RFC 7592 DELETE request failed: ")
    assert client.registration_access_token is None
    assert "fixture-rat" not in result


def test_revoked_client_is_not_reported_live():
    with fixture(CLIENT_DELETE="ok") as base:
        text = _cli(base)
    assert "Client Removal: deleted: client_id dcr-client-1, RFC 7592 DELETE HTTP 204" in text.stdout
    assert "STILL LIVE" not in text.stdout + text.stderr
