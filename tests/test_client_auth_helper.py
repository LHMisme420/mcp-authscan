"""One helper places the client secret for the token exchange, token-cors and password-grant.

The acquired-mode token exchange (_token_cors_acquired), default-mode token-cors and
password-grant each set client_secret in the form and then called _basic_client_auth with a
method chosen at the call site. They now all go through _apply_client_secret, which chooses
the method (_token_auth_method) and puts the secret in the Basic header or the body.
Revocation is deliberately not routed through it: it always sends client_secret (empty for a
public client), PROBE_CONTRACT.md amendment for probe set 2026.11.02.
No secret is printed: assertions compare booleans and decoded values only.
"""
import base64
from urllib.parse import parse_qsl, unquote_plus

import pytest

from mcp_authscan import oauth_probes_v2 as probes

SECRET = "s3cr:et with space+plus"
CID = "client:one"
TOKEN = "http://127.0.0.1:1/token"
META_BOTH = {"authorization_endpoint": "http://127.0.0.1:1/authorize",
             "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]}
META_BASIC = {"authorization_endpoint": "http://127.0.0.1:1/authorize",
              "token_endpoint_auth_methods_supported": ["client_secret_basic"]}


@pytest.fixture
def sent(monkeypatch):
    captured = []

    def guard(req, *args, **kwargs):
        captured.append(req)
        return 400, {"Content-Type": "application/json"}, b'{"error": "unsupported_grant_type"}'

    monkeypatch.setattr(probes, "_egress_guard", guard)
    monkeypatch.setattr(probes, "_prompt_for_redirect", lambda *a: "pasted")
    monkeypatch.setattr(probes, "_code_from_pasted", lambda *a: ("the-code", None, None))
    for name in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI",
                 "MCPAUTHSCAN_TOKEN_ENDPOINT_AUTH_METHOD"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", CID)
    monkeypatch.setenv("MCPAUTHSCAN_CLIENT_SECRET", SECRET)
    monkeypatch.setenv("MCPAUTHSCAN_REDIRECT_URI", "http://localhost/cb")
    return captured


def _placement(req):
    """('basic' | 'body' | 'none', client_id in form) for one captured request."""
    form = dict(parse_qsl(req.data.decode("ascii"), keep_blank_values=True))
    value = req.get_header("Authorization") or ""
    if value.startswith("Basic "):
        cid, _, secret = base64.b64decode(value[6:]).decode("utf-8").partition(":")
        ok = (unquote_plus(cid), unquote_plus(secret)) == (CID, SECRET) and "client_secret" not in form
        return ("basic" if ok else "bad-basic"), form.get("client_id") == CID
    if "client_secret" in form:
        return ("body" if form["client_secret"] == SECRET else "bad-body"), form.get("client_id") == CID
    return "none", form.get("client_id") == CID


def _three_paths(metadata):
    probes._token_cors_acquired(TOKEN, metadata, None, None)   # environment client
    probes.probe_token_cors(TOKEN, metadata=metadata)
    probes.probe_password_grant(TOKEN, metadata=metadata)


def test_all_three_paths_call_the_one_helper(sent, monkeypatch):
    calls = []
    real = probes._apply_client_secret

    def spy(req, form, client_id, secret, client=None, metadata=None):
        calls.append((client_id == CID, secret == SECRET, metadata is META_BASIC))
        return real(req, form, client_id, secret, client=client, metadata=metadata)

    monkeypatch.setattr(probes, "_apply_client_secret", spy)
    _three_paths(META_BASIC)
    assert len(sent) == 3
    assert calls == [(True, True, True)] * 3


@pytest.mark.parametrize("metadata,env_method,expected", [
    (META_BOTH, None, "body"),
    (META_BASIC, None, "basic"),
    (META_BOTH, "client_secret_basic", "basic"),
    (META_BASIC, "client_secret_post", "body"),
])
def test_three_paths_choose_the_same_auth_method(sent, monkeypatch, metadata, env_method, expected):
    if env_method:
        monkeypatch.setenv("MCPAUTHSCAN_TOKEN_ENDPOINT_AUTH_METHOD", env_method)
    _three_paths(metadata)
    assert [_placement(r) for r in sent] == [(expected, True)] * 3


@pytest.mark.parametrize("registered_method,expected_both,expected_basic_only", [
    ("client_secret_basic", "basic", "basic"), ("client_secret_post", "body", "body"),
    ("none", "body", "body"),
    (None, "body", "basic")])   # no token_endpoint_auth_method returned: the metadata decides
def test_helper_follows_the_registration_response(registered_method, expected_both, expected_basic_only):
    """A method the registration response returned decides, whatever the metadata says."""
    from urllib.request import Request
    client = probes._Client(CID, "http://localhost/cb", "registered", secret=SECRET,
                            auth_method=registered_method)
    for metadata, expected in ((META_BOTH, expected_both), (META_BASIC, expected_basic_only)):
        req, form = Request(TOKEN, method="POST"), {"client_id": CID}
        probes._apply_client_secret(req, form, CID, SECRET, client=client, metadata=metadata)
        req.data = __import__("urllib.parse").parse.urlencode(form).encode("ascii")
        assert _placement(req) == (expected, True)
