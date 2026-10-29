"""Dynamic client registration sends grant_types ["authorization_code", "refresh_token"]
(PROBE_CONTRACT.md "Client source", probe set 2026.11.01).

A live server refused the registration with 400 invalid_client_metadata, error_description
"grant_types must be authorization_code and refresh_token". Fixture branch REGISTRATION=grant_types
gives that refusal unless grant_types is exactly that set. Local fixture only.
"""
import json

from mcp_authscan import oauth_probes_v2 as probes
from tests.test_dcr_client_source import scope, _assess  # noqa: F401 (autouse: local scope, no env client)
from tests.test_probes_pkce_redirect import fixture

R = "http://localhost/mcp-authscan/callback"


def test_registration_payload_grant_types(monkeypatch):
    sent = {}

    def capture(req, **kw):
        sent.update(json.loads(req.data.decode("utf-8")))
        return 400, {}, b'{"error": "invalid_client_metadata"}'

    monkeypatch.setattr(probes, "_egress_guard", capture)
    probes._register_once("http://127.0.0.1:1/register", R)
    assert sent["grant_types"] == ["authorization_code", "refresh_token"]
    assert sent["response_types"] == ["code"] and sent["token_endpoint_auth_method"] == "none"


def test_grant_types_rule_server_registers_the_client():
    with fixture(REGISTRATION="grant_types") as base:
        by_name, report = _assess(base)
    assert report["client_registered"] is True, report["registration"]
    assert report["client_source"] == "registered" and report["redirect_uri"] == R
    assert by_name["pkce-s256"].status == "PASS", by_name["pkce-s256"].detail
    assert by_name["redirect-uri-exact"].status == "PASS", by_name["redirect-uri-exact"].detail
    assert report["client_removal"] == ("client removal is out of scope for this tool: client_id %s registered "
                                        "at %s by this run was not removed" % (report["client_id"], base))
