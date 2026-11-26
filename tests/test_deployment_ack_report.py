"""Deployment Acknowledgment Proof: signed report integration and offline verification.

A real scan (python -m mcp_authscan) runs against a local TLS MCP fixture on 127.0.0.1
with an ephemeral CA and an ephemeral Ed25519 signing key; no production key, trust
anchor or external network is involved.
"""
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import deployment_ack as dap
from mcp_authscan import report_signing
from mcp_authscan import report_verify as rv
from mcp_authscan import verification
from tests.dap_fixture import PUBLICATION_PATH, FixtureState, make_pki, text_reply, tls_server

ROOT = Path(__file__).resolve().parents[1]


def _scan(target, challenge_path, tmp, env, *extra):
    argv = [sys.executable, "-m", "mcp_authscan", target,
            "--contact", "validation@example.com", "--authorized-by", "Fixture operator",
            "--auth-basis", "Owned loopback test fixture", "--allow-private",
            "--deployment-challenge", str(challenge_path),
            "--evidence-dir", str(tmp / "evidence"), "--ledger-dir", str(tmp / "ledgers"),
            "--json", *extra]
    return subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=240)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("dap-report")
    pki = make_pki(tmp)
    key = Ed25519PrivateKey.generate()
    keyfile = tmp / "signing.pem"
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    keyfile.chmod(0o600)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    entry = {"key_id": hashlib.sha256(raw).hexdigest(), "alg": "ed25519",
             "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}
    keys_path = tmp / "keys.json"
    keys_path.write_text(json.dumps({"keys": [entry]}))
    env = {k: v for k, v in os.environ.items()
           if k not in ("SSL_CERT_DIR", "MCPAUTHSCAN_TOKEN", "HTTPS_PROXY", "https_proxy")}
    env.update(SSL_CERT_FILE=pki["ca.pem"], MCP_AUTHSCAN_SIGNING_KEY=str(keyfile),
               MCP_AUTHSCAN_LEDGER_DIR=str(tmp / "ledgers"), PYTHONPATH=str(ROOT))
    state = FixtureState()
    with tls_server(pki["leaf.pem"], pki["leaf.key"], state) as port:
        target = "https://127.0.0.1:%d/mcp" % port
        challenge = dap.create_challenge(target, binding_scope="dedicated-host")
        challenge_path = tmp / "challenge.json"
        challenge_path.write_text(json.dumps(challenge))
        state.routes[PUBLICATION_PATH] = text_reply(challenge["nonce"])
        result = _scan(target, challenge_path, tmp, env, "--sign")
        seen_after_scan = list(state.requests)
        yield {"tmp": tmp, "pki": pki, "key": key, "anchor": verification.anchor_from_keys([entry]),
               "keys_path": keys_path, "env": env, "state": state, "port": port, "target": target,
               "challenge": challenge, "challenge_path": challenge_path, "result": result,
               "seen": seen_after_scan}


@pytest.fixture
def report(world):
    result = world["result"]
    assert result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


@pytest.fixture
def trusted(world, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", world["pki"]["ca.pem"])
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


def _bytes(report):
    return json.dumps(report).encode()


def _resign(report, key):
    forged = copy.deepcopy(report)
    forged.pop("signature", None)
    assert report_signing.sign_report(forged, rv.signed_content(forged, forged["findings"]), key=key)
    return forged


def test_scan_binds_acknowledgment_into_sig_version_5(world, report):
    assert report["sig_version"] == 5
    record = report["deployment_acknowledgment"]
    assert record["result"] == "ACKNOWLEDGED", record["reason"]
    assert record["challenge_id"] == world["challenge"]["challenge_id"]
    assert record["requested_target"] == world["target"]
    assert record["publication_origin"] == "https://127.0.0.1:%d" % world["port"]
    assert record["binding_scope"] == "dedicated-host"
    assert record["statement"] == dap.STATEMENT
    obs = record["observation"]
    assert obs["response_sha256"] == hashlib.sha256(world["challenge"]["nonce"].encode()).hexdigest()
    assert obs["tls_certificate_verified"] is True and obs["credentials_sent"] is False
    gets = [r for r in world["seen"] if r["path"] == PUBLICATION_PATH]
    assert len(gets) == 1 and "authorization" not in gets[0]["headers"]

    engine = verification.verify(_bytes(report), anchor=world["anchor"])
    assert engine["failed_stage"] is None
    assert engine["integrity"]["verdict"] == "INTACT"
    assert engine["authenticity"]["verdict"] == "SIGNED BY"
    assert engine["deployment_acknowledgment"]["verdict"] == "VERIFIED"
    assert engine["probe_statuses"]["verdict"] == "VERIFIED"

    out = dap.verify_report(_bytes(report), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == "ACKNOWLEDGED", out["reason"]
    assert all(c["verdict"] == "PASS" for c in out["checks"].values()), out["checks"]
    assert out["network_request"].startswith("NOT INDEPENDENTLY PROVEN")


def test_acknowledgment_is_outside_report_hash(report):
    assert "deployment_acknowledgment" not in report["hash_covers"]
    stripped = {k: v for k, v in report.items() if k not in ("deployment_acknowledgment", "report_hash")}
    assert rv.compute(stripped, report["findings"])[0] == report["report_hash"]


@pytest.mark.parametrize("path, value", [
    (("result",), "MISMATCH"),
    (("nonce",), "d" * 64),
    (("binding_scope",), "unknown"),
    (("statement",), "This report proves the deployment is secure."),
    (("observation", "response_body_b64"), base64.b64encode(b"e" * 64).decode()),
    (("observation", "observed_at"), "2020-01-01T00:00:00Z"),
    (("challenge", "expires_at"), "2099-01-01T00:00:00Z"),
])
def test_fail_altered_signed_acknowledgment(world, report, path, value):
    tampered = copy.deepcopy(report)
    node = tampered["deployment_acknowledgment"]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    engine = verification.verify(_bytes(tampered), anchor=world["anchor"])
    assert engine["authenticity"]["verdict"] == "SIGNATURE INVALID"
    assert dap.verify_report(_bytes(tampered), world["challenge"], anchor=world["anchor"])["verdict"] == "INVALID"


def test_fail_unsigned_report(world, report):
    unsigned = copy.deepcopy(report)
    unsigned.pop("signature")
    out = dap.verify_report(_bytes(unsigned), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == "INVALID"
    assert "never established" in out["reason"]


def test_fail_downgraded_signature_form(world, report):
    for version in (1, 2, 3, 4):
        downgraded = dict(copy.deepcopy(report), sig_version=version)
        engine = verification.verify(_bytes(downgraded), anchor=world["anchor"])
        assert engine["authenticity"]["verdict"] == "DIVERGENCE"
        assert dap.verify_report(_bytes(downgraded), world["challenge"],
                                 anchor=world["anchor"])["verdict"] == "INVALID"


def test_older_forms_refuse_an_uncovered_acknowledgment(report):
    for version in (1, 2, 3, 4):
        with pytest.raises(ValueError, match="does not cover deployment_acknowledgment"):
            rv.signed_content(dict(report, sig_version=version), report["findings"])


def test_fail_untrusted_signing_key(world, report):
    # The packaged (production) anchor does not hold the ephemeral key.
    out = dap.verify_report(_bytes(report), world["challenge"], anchor="packaged")
    assert out["verdict"] == "INVALID"
    other = verification.anchor_from_keys([{"key_id": "x" * 64, "alg": "ed25519",
                                            "public_key": base64.urlsafe_b64encode(b"\1" * 32).rstrip(b"=").decode()}])
    assert dap.verify_report(_bytes(report), world["challenge"], anchor=other)["verdict"] == "INVALID"


def test_fail_replay_against_another_target(world, report):
    other = dap.create_challenge("https://127.0.0.1:%d/other" % world["port"])
    out = dap.verify_report(_bytes(report), other, anchor=world["anchor"])
    assert out["verdict"] == "INVALID" and out["checks"]["reviewer_challenge"]["verdict"] == "FAIL"
    # Even a key holder cannot move a record onto another target: the challenge binds it.
    forged = copy.deepcopy(report)
    forged["deployment_acknowledgment"]["target"] = "https://127.0.0.1:%d/other" % world["port"]
    forged = _resign(forged, world["key"])
    out = dap.verify_report(_bytes(forged), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == "INVALID" and out["checks"]["target_identity"]["verdict"] == "FAIL"


def test_fail_report_bound_to_a_scanner_generated_challenge(world, report):
    # Same target, but not the challenge this reviewer issued.
    mine = dap.create_challenge(world["target"])
    assert dap.verify_report(_bytes(report), mine, anchor=world["anchor"])["verdict"] == "INVALID"


def test_fail_reused_challenge_outside_validity(world, report, trusted):
    expired_at = dap._parse(world["challenge"]["expires_at"])
    forged = copy.deepcopy(report)
    forged["deployment_acknowledgment"]["observation"]["observed_at"] = dap._fmt(expired_at + timedelta(seconds=5))
    forged = _resign(forged, world["key"])
    out = dap.verify_report(_bytes(forged), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == "INVALID"
    assert out["checks"]["result_recomputation"]["verdict"] == "FAIL"
    # A consistent EXPIRED record verifies as EXPIRED, never ACKNOWLEDGED.
    forged["deployment_acknowledgment"]["result"] = "EXPIRED"
    forged = _resign(forged, world["key"])
    assert dap.verify_report(_bytes(forged), world["challenge"], anchor=world["anchor"])["verdict"] == "EXPIRED"
    # Reviewer-side live confirmation after expiry makes no request and is EXPIRED.
    before = len(world["state"].requests)
    live = dap.live_confirmation(world["challenge"], allow_private=True, now=expired_at)
    assert live["result"] == "EXPIRED"
    assert len(world["state"].requests) == before


def test_fail_upgraded_result_without_matching_observation(world, report):
    forged = copy.deepcopy(report)
    obs = forged["deployment_acknowledgment"]["observation"]
    body = b"f" * 64
    obs.update(response_body_b64=base64.b64encode(body).decode(), response_sha256=hashlib.sha256(body).hexdigest())
    forged = _resign(forged, world["key"])
    out = dap.verify_report(_bytes(forged), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == "INVALID"
    obs = forged["deployment_acknowledgment"]["observation"]
    obs["response_sha256"] = "0" * 64
    forged = _resign(forged, world["key"])
    out = dap.verify_report(_bytes(forged), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == "INVALID" and out["checks"]["response_digest"]["verdict"] == "FAIL"


def test_reviewer_live_confirmation_is_separate(world, trusted):
    live = dap.live_confirmation(world["challenge"], allow_private=True)
    assert live["result"] == "ACKNOWLEDGED", live["reason"]
    assert dap.live_confirmation(world["challenge"], allow_private=False)["result"] == "NOT_OBSERVED"


def test_cli_verify_report(world, report, tmp_path, trusted, capsys):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report))
    argv = ["verify-report", "--report", str(path), "--challenge", str(world["challenge_path"]),
            "--trust-anchor", str(world["keys_path"])]
    assert dap.main(argv) == 0
    out = capsys.readouterr().out
    assert out.startswith("OFFLINE ACKNOWLEDGED") and "NOT INDEPENDENTLY PROVEN" in out
    assert dap.main(argv + ["--live", "--allow-private"]) == 0
    assert "LIVE ACKNOWLEDGED" in capsys.readouterr().out
    assert dap.main(argv + ["--live"]) == 1   # live check refused without explicit private authorization
    capsys.readouterr()  # discard output from the refused live check
    tampered = copy.deepcopy(report)
    tampered["deployment_acknowledgment"]["result"] = "MISMATCH"
    path.write_text(json.dumps(tampered))
    assert dap.main(argv) == 1
    assert capsys.readouterr().out.startswith("OFFLINE INVALID")


def test_scan_refuses_challenge_for_another_target(world):
    other = dap.create_challenge("https://127.0.0.1:%d/other" % world["port"])
    path = world["tmp"] / "other-challenge.json"
    path.write_text(json.dumps(other))
    before = len(world["state"].requests)
    result = _scan(world["target"], path, world["tmp"], world["env"], "--sign")
    assert result.returncode == 2, result.stderr
    assert "INVALID" in result.stderr and not result.stdout.strip()
    assert len(world["state"].requests) == before


def test_scan_requires_sign_for_acknowledgment(world):
    before = len(world["state"].requests)
    result = _scan(world["target"], world["challenge_path"], world["tmp"], world["env"])
    assert result.returncode == 2
    assert "requires --sign" in result.stderr
    assert len(world["state"].requests) == before
