"""Deployment Acknowledgment Proof: challenge creation and live observation.

All traffic goes to a local TLS fixture on 127.0.0.1 under an ephemeral CA; the
synthetic name dap.test is answered by a test resolver that refuses every other name.
"""
import json
import socket
from datetime import timedelta

import pytest

from mcp_authscan import deployment_ack as dap
from tests.dap_fixture import (FIXTURE_HOST, PUBLICATION_PATH, FixtureState, Resolver, make_pki,
                               slow_reply, text_reply, tls_server, unbounded_reply)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    return make_pki(tmp_path_factory.mktemp("dap-pki"))


@pytest.fixture
def trust(pki, monkeypatch):
    # The default TLS context trusts only the ephemeral fixture CA; a proxy is configured
    # in the environment to prove the transport ignores it.
    monkeypatch.setenv("SSL_CERT_FILE", pki["ca.pem"])
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("https_proxy", "http://127.0.0.1:9")
    return pki


@pytest.fixture
def resolve(monkeypatch):
    def install(*answers):
        resolver = Resolver(socket.getaddrinfo, answers or (["127.0.0.1"],))
        monkeypatch.setattr(socket, "getaddrinfo", resolver)
        return resolver
    return install


@pytest.fixture
def server(trust):
    state = FixtureState()
    with tls_server(trust["leaf.pem"], trust["leaf.key"], state) as port:
        yield state, port


def _challenge(port, **kw):
    return dap.create_challenge("https://%s:%d/mcp" % (FIXTURE_HOST, port), **kw)


# ---- challenge creation -------------------------------------------------------------

def test_challenge_shape_and_binding():
    c = dap.create_challenge("https://Example.COM:8443/mcp")
    assert sorted(c) == sorted(["schema", "nonce", "target", "challenge_id", "publication_path",
                                "created_at", "expires_at", "binding_scope"])
    assert c["schema"] == "deployment-challenge-v1"
    assert len(c["nonce"]) == 64 and int(c["nonce"], 16) >= 0
    assert c["target"] == "https://example.com:8443/mcp"
    assert c["publication_path"] == PUBLICATION_PATH
    assert c["binding_scope"] == "unknown"
    assert c["challenge_id"] == dap.challenge_id(c)
    assert dap.publication_url(c["target"]) == "https://example.com:8443" + PUBLICATION_PATH
    assert dap.create_challenge("https://example.com/mcp")["nonce"] != c["nonce"]
    dap.validate_challenge(c)


@pytest.mark.parametrize("field, value", [
    ("nonce", "b" * 64), ("target", "https://other.example/mcp"), ("expires_at", "2099-01-01T00:00:00Z"),
    ("binding_scope", "dedicated-host"),
])
def test_altered_challenge_fails_its_identifier(field, value):
    c = dap.create_challenge("https://example.com/mcp")
    c[field] = value
    with pytest.raises(dap.ChallengeInvalid):
        dap.validate_challenge(c)


@pytest.mark.parametrize("target", [
    "http://example.com/mcp", "https://user:pw@example.com/mcp", "https://example.com/mcp?k=v",
    "https://example.com/mcp#x", "ftp://example.com/", "https:///mcp", "https://exa mple.com/",
])
def test_challenge_refuses_targets_it_would_have_to_rewrite(target):
    with pytest.raises(dap.ChallengeInvalid):
        dap.create_challenge(target)


def test_cli_create_writes_once(tmp_path, capsys):
    out = tmp_path / "challenge.json"
    assert dap.main(["create", "--target", "https://example.com/mcp", "--output", str(out),
                     "--binding-scope", "shared-provider-host"]) == 0
    c = json.loads(out.read_text())
    assert dap.validate_challenge(c)["binding_scope"] == "shared-provider-host"
    before = out.read_bytes()
    assert dap.main(["create", "--target", "https://example.com/mcp", "--output", str(out)]) == 2
    assert out.read_bytes() == before


# ---- observation ----------------------------------------------------------------------

def test_pass_exact_valid_nonce(server, resolve):
    state, port = server
    resolver = resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"] + "\n")
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.ACKNOWLEDGED, rec["reason"]
    obs = rec["observation"]
    assert obs["http_status"] == 200 and obs["tls_certificate_verified"] is True
    assert obs["resolved_address"] == "127.0.0.1"
    assert obs["url"] == "https://%s:%d%s" % (FIXTURE_HOST, port, PUBLICATION_PATH)
    assert rec["publication_origin"] == "https://%s:%d" % (FIXTURE_HOST, port)
    assert resolver.lookups == 1
    # No credentials, cookies or proxy: the request reached the fixture directly, bare.
    (seen,) = state.requests
    assert seen["path"] == PUBLICATION_PATH
    assert not {"authorization", "cookie", "proxy-authorization"} & set(seen["headers"])
    assert rec["statement"] == dap.STATEMENT


def test_fail_wrong_nonce(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply("0" * 64)
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.MISMATCH


def test_fail_nonce_with_extra_content(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(" " + c["nonce"] + "\n\n")
    assert dap.observe(c, requested_target=c["target"], allow_private=True)["result"] == dap.MISMATCH


def test_fail_expired_challenge_makes_no_request(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port, ttl=60)
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"])
    later = dap._parse(c["expires_at"]) + timedelta(seconds=1)
    rec = dap.observe(c, requested_target=c["target"], allow_private=True, now=later)
    assert rec["result"] == dap.EXPIRED
    assert rec["observation"]["request_attempted"] is False
    assert state.requests == []


def test_fail_missing_challenge(server, resolve):
    _state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.NOT_OBSERVED
    assert rec["observation"]["http_status"] == 404


def test_fail_http_redirect_is_not_followed(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(b"", status=302, headers={"Location": "/elsewhere"})
    state.routes["/elsewhere"] = text_reply(c["nonce"])
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.NOT_OBSERVED
    assert "redirect refused" in rec["reason"]
    assert state.paths_seen() == [PUBLICATION_PATH]


def test_fail_invalid_certificate(trust, resolve):
    state = FixtureState()
    with tls_server(trust["rogue.pem"], trust["rogue.key"], state) as port:
        resolve(["127.0.0.1"])
        c = _challenge(port)
        state.routes[PUBLICATION_PATH] = text_reply(c["nonce"])
        rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.NOT_OBSERVED
    assert "TLS" in rec["reason"]
    assert rec["observation"]["tls_certificate_verified"] is False
    assert state.requests == []


def test_fail_dns_rebinding_mixed_answer(server, resolve):
    state, port = server
    resolve(["8.8.8.8", "127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"])
    rec = dap.observe(c, requested_target=c["target"], allow_private=False)
    assert rec["result"] == dap.NOT_OBSERVED
    assert "destination refused" in rec["reason"]
    assert state.requests == []


def test_dns_rebinding_after_check_cannot_redirect_connection(server, resolve):
    # The name resolves once; a later answer (rebinding to another address) is never consulted.
    state, port = server
    resolver = resolve(["127.0.0.1"], ["10.9.9.9"], ["169.254.169.254"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"])
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.ACKNOWLEDGED
    assert resolver.lookups == 1
    assert rec["observation"]["resolved_address"] == "127.0.0.1"


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"])
def test_fail_private_destination_without_authorization(server, resolve, address):
    state, port = server
    resolve([address])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"])
    rec = dap.observe(c, requested_target=c["target"], allow_private=False)
    assert rec["result"] == dap.NOT_OBSERVED
    assert "destination refused" in rec["reason"]
    assert state.requests == []


def test_fail_dns_failure(trust, monkeypatch):
    def broken(*_a, **_k):
        raise socket.gaierror(socket.EAI_NONAME, "no such host")
    monkeypatch.setattr(socket, "getaddrinfo", broken)
    c = dap.create_challenge("https://%s/mcp" % FIXTURE_HOST)
    rec = dap.observe(c, requested_target=c["target"], allow_private=False)
    assert rec["result"] == dap.NOT_OBSERVED


def test_fail_oversize_response(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = unbounded_reply(dap.MAX_RESPONSE_BYTES * 64)
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.NOT_OBSERVED
    assert "exceeded" in rec["reason"]


def test_fail_declared_oversize_response(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"] + "x" * 2048)
    rec = dap.observe(c, requested_target=c["target"], allow_private=True)
    assert rec["result"] == dap.NOT_OBSERVED


def test_fail_timeout(server, resolve):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    state.routes[PUBLICATION_PATH] = slow_reply(3, c["nonce"])
    rec = dap.observe(c, requested_target=c["target"], allow_private=True, timeout=1)
    assert rec["result"] == dap.NOT_OBSERVED


def test_fail_replay_against_another_target(server, resolve):
    _state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    for other in ("https://%s:%d/other" % (FIXTURE_HOST, port), "https://%s:%d/mcp" % (FIXTURE_HOST, port + 1),
                  "http://%s:%d/mcp" % (FIXTURE_HOST, port)):
        with pytest.raises(dap.ChallengeInvalid):
            dap.observe(c, requested_target=other, allow_private=True)


def test_cli_verify_exit_codes(server, resolve, tmp_path, capsys):
    state, port = server
    resolve(["127.0.0.1"])
    c = _challenge(port)
    path = tmp_path / "c.json"
    path.write_text(json.dumps(c))
    state.routes[PUBLICATION_PATH] = text_reply(c["nonce"])
    assert dap.main(["verify", "--challenge", str(path), "--allow-private"]) == 0
    assert capsys.readouterr().out.startswith("ACKNOWLEDGED")
    # Without explicit authorization the loopback destination is refused.
    assert dap.main(["verify", "--challenge", str(path)]) == 1
    assert capsys.readouterr().out.startswith("NOT_OBSERVED")
    c["nonce"] = "c" * 64
    path.write_text(json.dumps(c))
    assert dap.main(["verify", "--challenge", str(path), "--allow-private"]) == 1
    assert capsys.readouterr().out.startswith("INVALID")
