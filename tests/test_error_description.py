"""A server's error_description is carried verbatim into registration reasons and revocation
results, text and JSON (PROBE_CONTRACT.md "Client source", "Result forms").

Form: `HTTP <status> error=<code> error_description="<verbatim>"`, one line: a newline in the
description is written as the two characters \\n. A description that contains a value this run
sent (token, code, code_verifier, client_secret, registration_access_token) is withheld:
`error_description withheld: it contained the <name> this run sent`. Local fixture only
(fixture_oauth.py REGISTRATION=fail|multiline, REVOCATION=described|echo).
"""
import json

from mcp_authscan import oauth_probes_v2 as probes
from tests.test_dcr_client_source import _assess, _cli as _plain_cli, scope  # noqa: F401 (autouse)
from tests.test_probes_pkce_redirect import fixture
from tests.test_token_cors_acquired import SECRETS, _cli, _no_secret
from tests.test_token_still_live import _entries

R = "http://localhost/mcp-authscan/callback"
ML = 'error_description="first line of the refusal\\nsecond line of the refusal"'


def _body(**doc):
    return json.dumps(doc).encode()


def test_status_text_forms():
    assert probes._status_text(503, b"") == "HTTP 503"
    assert probes._status_text(401, _body(error="invalid_client")) == "HTTP 401 error=invalid_client"
    assert probes._status_text(400, _body(error="invalid_request", error_description='a "b"\r\nc\nd')) == \
        'HTTP 400 error=invalid_request error_description="a "b"\\nc\\nd"'
    sent = {"access_token": "tok-123", "client_secret": "sec-456"}
    assert probes._status_text(400, _body(error="invalid_request", error_description="no sec-456 here"), sent) == \
        "HTTP 400 error=invalid_request error_description withheld: it contained the client_secret this run sent"
    assert probes._status_text(400, _body(error="x", error_description="ok"), {"client_secret": ""}) == \
        'HTTP 400 error=x error_description="ok"'


def test_registration_reason_carries_description():
    with fixture(REGISTRATION="fail") as base:
        by_name, report = _assess(base)
    want = 'registration returned HTTP 400 error=invalid_client_metadata error_description="registration disabled on this fixture"'
    assert report["registration"] == want
    assert by_name["pkce-s256"].detail == "Dynamic client registration unavailable: " + want
    assert report["redirect_candidates_tried"] == [{"redirect_uri": R, "result": "refused, " + want[len("registration returned "):]}]


def test_multiline_description_stays_on_one_line_in_text_and_json():
    with fixture(REGISTRATION="multiline") as base:
        text = _plain_cli(base)
        js = _plain_cli(base, "--json")
    want = "registration returned HTTP 400 error=invalid_client_metadata " + ML
    assert "Registration: %s\n" % want in text.stdout
    assert "second line of the refusal\n" not in text.stdout.replace("\\n", "")
    entry = json.loads(js.stdout)["client_registration"][0]
    assert entry["registration"] == want


def test_revocation_results_carry_description():
    with fixture(REVOCATION="described") as base:
        runs = [_cli(base, "--acquire-token"), _cli(base, "--acquire-token", "--json")]
    text, js = runs[0][0], runs[1][0]
    entry = _entries(js.stdout)[0]
    nc = "revocation not confirmed (HTTP 400 error=invalid_request %s)" % ML
    assert "access_token " + nc in entry["token_revocation"]
    assert "refresh_token " + nc in entry["token_revocation"]
    assert entry["client_removal"].startswith("client removal is out of scope for this tool")   # never /revoke
    assert "access_token " + nc in text.stdout
    for p, _, _ in runs:
        _no_secret(p.stdout, p.stderr)


def test_description_echoing_a_sent_value_is_withheld():
    with fixture(REVOCATION="echo") as base:
        runs = [_cli(base, "--acquire-token"), _cli(base, "--acquire-token", "--json")]
    text, js = runs[0][0], runs[1][0]
    entry = _entries(js.stdout)[0]
    w = "HTTP 400 error=invalid_request error_description withheld: it contained the %s this run sent"
    assert "access_token revocation not confirmed (%s)" % (w % "access_token") in entry["token_revocation"]
    assert "refresh_token revocation not confirmed (%s)" % (w % "refresh_token") in entry["token_revocation"]
    assert entry["client_removal"].startswith("client removal is out of scope for this tool")   # never /revoke
    assert "access_token revocation not confirmed (%s)" % (w % "access_token") in text.stdout
    for p, _, _ in runs:
        _no_secret(p.stdout, p.stderr)
        assert "is not accepted here" not in p.stdout + p.stderr
