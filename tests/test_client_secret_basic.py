"""client_secret_basic at the token and revocation endpoints (probe set 2026.11.03,
PROBE_CONTRACT.md "Client authentication at the token endpoint").

A client whose registration response says token_endpoint_auth_method client_secret_basic, an
environment client with MCPAUTHSCAN_TOKEN_ENDPOINT_AUTH_METHOD=client_secret_basic, or an
environment client at a server whose metadata advertises client_secret_basic and not
client_secret_post sends its secret only in an HTTP Basic header (RFC 6749 2.3.1, client_id and
secret form-urlencoded first), never in the body. Anything else keeps client_secret_post.
No secret is printed: these tests compare decoded values and assert on booleans only.
"""
import base64
from urllib.parse import parse_qsl, unquote_plus

import pytest

from mcp_authscan import oauth_probes_v2 as probes

SECRET = "s3cr:et with space+plus"   # characters that RFC 6749 2.3.1 form-encoding changes
CID = "client:one"


@pytest.fixture
def sent(monkeypatch):
    """Capture every request the probes send; answer 400 invalid_client with a JSON body."""
    captured = []

    def guard(req, *args, **kwargs):
        captured.append(req)
        return 400, {"Content-Type": "application/json"}, b'{"error": "unsupported_grant_type"}'

    monkeypatch.setattr(probes, "_egress_guard", guard)
    for name in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI",
                 "MCPAUTHSCAN_TOKEN_ENDPOINT_AUTH_METHOD"):
        monkeypatch.delenv(name, raising=False)
    return captured


def _basic(req):
    """(client_id, secret) decoded from the request's Basic header, or None."""
    value = req.get_header("Authorization") or ""
    if not value.startswith("Basic "):
        return None
    cid, _, secret = base64.b64decode(value[6:]).decode("utf-8").partition(":")
    return unquote_plus(cid), unquote_plus(secret)


def _form(req):
    return dict(parse_qsl(req.data.decode("ascii"), keep_blank_values=True))


def _registered(method):
    return probes._Client(CID, "http://localhost/mcp-authscan/callback", "registered",
                          secret=SECRET, auth_method=method)


META_BOTH = {"revocation_endpoint": "http://127.0.0.1:1/revoke",
             "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"]}
META_BASIC = {"revocation_endpoint": "http://127.0.0.1:1/revoke",
              "token_endpoint_auth_methods_supported": ["client_secret_basic"]}


def test_revocation_uses_basic_for_a_client_registered_as_client_secret_basic(sent):
    probes._revoke_tokens(META_BOTH, _registered("client_secret_basic"), [("access_token", "tok")])
    (req,) = sent
    assert _basic(req) == (CID, SECRET)
    form = _form(req)
    assert "client_secret" not in form and form["client_id"] == CID and form["token_type_hint"] == "access_token"


@pytest.mark.parametrize("method", ["client_secret_post", "none", None])
def test_revocation_keeps_the_body_secret_otherwise(sent, method):
    probes._revoke_tokens(META_BOTH, _registered(method), [("access_token", "tok")])
    (req,) = sent
    assert req.get_header("Authorization") is None
    assert (_form(req)["client_secret"] == SECRET) is True


def test_registered_method_wins_over_metadata(sent):
    probes._revoke_tokens(META_BASIC, _registered("client_secret_post"), [("access_token", "tok")])
    assert sent[0].get_header("Authorization") is None
    probes._revoke_tokens(META_BASIC, _registered(None), [("access_token", "tok")])
    assert _basic(sent[1]) == (CID, SECRET)


def test_public_client_sends_empty_secret_in_the_body(sent):
    client = probes._Client(CID, "http://localhost/cb", "registered", secret=None, auth_method="client_secret_basic")
    probes._revoke_tokens(META_BOTH, client, [("access_token", "tok")])
    assert sent[0].get_header("Authorization") is None and _form(sent[0])["client_secret"] == ""


def _env(monkeypatch, method=None):
    monkeypatch.setenv("MCPAUTHSCAN_CLIENT_ID", CID)
    monkeypatch.setenv("MCPAUTHSCAN_CLIENT_SECRET", SECRET)
    if method:
        monkeypatch.setenv("MCPAUTHSCAN_TOKEN_ENDPOINT_AUTH_METHOD", method)


@pytest.mark.parametrize("meta,method,basic", [
    (None, None, False),
    (META_BOTH, None, False),
    (META_BASIC, None, True),
    (META_BOTH, "client_secret_basic", True),
    (META_BASIC, "client_secret_post", False),
])
def test_env_client_password_grant_and_token_cors(sent, monkeypatch, meta, method, basic):
    _env(monkeypatch, method)
    probes.probe_password_grant("http://127.0.0.1:1/token", metadata=meta)
    probes.probe_token_cors("http://127.0.0.1:1/token", metadata=meta)
    assert len(sent) == 2
    for req in sent:
        form = _form(req)
        assert form["client_id"] == CID
        if basic:
            assert _basic(req) == (CID, SECRET) and "client_secret" not in form
        else:
            assert req.get_header("Authorization") is None and (form["client_secret"] == SECRET) is True


def test_basic_header_value_withheld_from_an_echoing_error_description(monkeypatch):
    """A server that echoes the Authorization header in error_description must not get it printed."""
    def guard(req, *args, **kwargs):
        echoed = req.get_header("Authorization")
        return 400, {}, ('{"error": "invalid_client", "error_description": "got %s"}' % echoed).encode()

    monkeypatch.setattr(probes, "_egress_guard", guard)
    _, summary = probes._revoke_tokens(META_BOTH, _registered("client_secret_basic"), [("access_token", "tok")])
    assert "Basic " not in summary and "withheld" in summary
