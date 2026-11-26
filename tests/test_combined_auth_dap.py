"""One sig_version 5 report carrying BOTH signed authentication assurance and a DAP record.

A real scan (python -m mcp_authscan) runs against a local TLS MCP fixture on 127.0.0.1
that enforces a synthetic bearer token, with an ephemeral CA and an ephemeral Ed25519
signing key. Signatures are created and verified with the real Ed25519 code; nothing
cryptographic is mocked. No production key, trust anchor or external network is used.
"""
import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import deployment_ack as dap
from mcp_authscan import policy_check, report_signing
from mcp_authscan import report_verify as rv
from mcp_authscan import verification
from mcp_authscan.authentication_assurance import derive_verdict
from tests.dap_fixture import PUBLICATION_PATH, FixtureState, make_pki, text_reply, tls_server

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-combined-test-token"
ASSURANCE_CHALLENGE = "c" * 64


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("combined")
    pki = make_pki(tmp)
    key = Ed25519PrivateKey.generate()
    keyfile = tmp / "signing.pem"
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    keyfile.chmod(0o600)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    entry = {"key_id": hashlib.sha256(raw).hexdigest(), "alg": "ed25519",
             "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}
    env = {k: v for k, v in os.environ.items()
           if k not in ("SSL_CERT_DIR", "HTTPS_PROXY", "https_proxy")}
    env.update(SSL_CERT_FILE=pki["ca.pem"], MCP_AUTHSCAN_SIGNING_KEY=str(keyfile), MCPAUTHSCAN_TOKEN=TOKEN,
               MCP_AUTHSCAN_LEDGER_DIR=str(tmp / "ledgers"), PYTHONPATH=str(ROOT))
    state = FixtureState()
    state.mcp_token = TOKEN
    with tls_server(pki["leaf.pem"], pki["leaf.key"], state) as port:
        target = "https://127.0.0.1:%d/mcp" % port
        challenge = dap.create_challenge(target, binding_scope="dedicated-host")
        challenge_path = tmp / "challenge.json"
        challenge_path.write_text(json.dumps(challenge))
        state.routes[PUBLICATION_PATH] = text_reply(challenge["nonce"])
        argv = [sys.executable, "-m", "mcp_authscan", target,
                "--contact", "validation@example.com", "--authorized-by", "Fixture operator",
                "--auth-basis", "Owned loopback test fixture", "--allow-private",
                "--authentication-assurance",
                "--deployment-challenge", str(challenge_path),
                "--deployment-challenge", ASSURANCE_CHALLENGE,
                "--evidence-dir", str(tmp / "evidence"), "--ledger-dir", str(tmp / "ledgers"),
                "--sign", "--json"]
        result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=240)
        assert result.stdout.strip(), result.stderr
        yield {"tmp": tmp, "pki": pki, "key": key, "entry": entry, "anchor": verification.anchor_from_keys([entry]),
               "state": state, "target": target, "challenge": challenge, "result": result,
               "report": json.loads(result.stdout), "argv": argv, "env": env}


@pytest.fixture
def trusted(world, monkeypatch):
    monkeypatch.setenv("SSL_CERT_FILE", world["pki"]["ca.pem"])
    monkeypatch.delenv("SSL_CERT_DIR", raising=False)


def _bytes(doc):
    return json.dumps(doc).encode()


def _sign(doc, key):
    doc = copy.deepcopy(doc)
    doc.pop("signature", None)
    assert report_signing.sign_report(doc, rv.signed_content(doc, doc["findings"]), key=key)
    return doc


def _gate_report(world, *, sig_version=5, content="scan", record="scan"):
    """A clean graded report for the fixture target carrying the scan's signed components."""
    scan = world["report"]
    doc = {
        "schema_version": 3, "hash_scheme": "verdict-v3", "tool_version": "1.1.34",
        "probe_set_version": "2026.11.19.3", "target": world["target"], "scan_mode": "anonymous",
        "counts": {}, "coverage": {}, "completed": True, "probes": [{"name": "P1", "status": "PASS"}],
        "status": "completed", "total_checks": 1, "findings_count": 0,
        "severity_counts": rv.severity_counts([]), "findings": [],
        "evidence": {"scheme": rv.EVIDENCE_SCHEME_V1, "states": []},
        "provenance": copy.deepcopy(scan["provenance"]),
        "content_observed": copy.deepcopy(scan["content_observed"]) if content == "scan" else content,
        "sig_version": sig_version,
    }
    if record is not None:
        doc[rv.DEPLOYMENT_KEY] = copy.deepcopy(scan[rv.DEPLOYMENT_KEY]) if record == "scan" else record
    doc["report_hash"] = rv.compute(doc, [])[0]
    return _sign(doc, world["key"])


def _policy(world, **extra):
    base = {"required-probes": ["P1"], "forbidden-findings": [], "trusted-signers": [world["entry"]["key_id"]]}
    base.update(extra)
    return base


def _full_policy(world, **extra):
    return _policy(world, **{"min-sig-version": 5, "declared-authentication-required": True,
                             "verified-authentication-required": True,
                             "deployment-acknowledgment-required": True,
                             "deployment-acknowledgment-challenge": world["challenge"],
                             "scope": {"operations": ["initialize"]}, **extra})


def _gate(world, tmp_path, doc, policy):
    rp, pp, kp = tmp_path / "report.json", tmp_path / "policy.json", tmp_path / "keys.json"
    rp.write_text(json.dumps(doc))
    pp.write_text(json.dumps(policy))
    kp.write_text(json.dumps([world["entry"]]))
    return policy_check.evaluate(str(rp), str(pp), str(kp))


# ---- J + A: the combined scan produces one signed form-5 report with both evidence sets ----

def test_j_combined_scan_produces_one_signed_form5_report(world):
    report = world["report"]
    assert report["sig_version"] == 5, world["result"].stderr
    content = report["content_observed"]
    assert "initialize" in content["operations"] and content["session_established"] is True
    assurance = content["authentication_assurance"]
    assert assurance["endpoint"] == world["target"]
    assert derive_verdict(assurance) == "VERIFIED", assurance
    # The 64-hex assurance challenge keeps its meaning; the DAP nonce is never used for it.
    assert assurance["deployment_challenge"] == ASSURANCE_CHALLENGE
    assert assurance["deployment_challenge"] != world["challenge"]["nonce"]
    record = report[rv.DEPLOYMENT_KEY]
    assert record["result"] == dap.ACKNOWLEDGED, record["reason"]
    assert record["challenge_id"] == world["challenge"]["challenge_id"]
    assert record["observation"]["tls_certificate_verified"] is True
    assert record["observation"]["credentials_sent"] is False
    gets = [r for r in world["state"].requests if r["path"] == PUBLICATION_PATH]
    assert len(gets) == 1 and "authorization" not in gets[0]["headers"]


def test_a_engine_verifies_every_form5_component(world):
    engine = verification.verify(_bytes(world["report"]), anchor=world["anchor"])
    assert engine["failed_stage"] is None
    assert engine["authenticity"]["verdict"] == "SIGNED BY"
    assert engine["authenticity"]["sig_version"] == 5
    assert engine["authenticity"]["covers"] == ["graded report", "evidence", "probes", "provenance",
                                                "content_observed.operations", "deployment_acknowledgment"]
    for name in ("evidence", "probe_statuses", "provenance", "operations", "deployment_acknowledgment"):
        assert engine[name]["verdict"] == "VERIFIED", (name, engine[name])
    out = dap.verify_report(_bytes(world["report"]), world["challenge"], anchor=world["anchor"])
    assert out["verdict"] == dap.ACKNOWLEDGED, out["reason"]
    assert all(c["verdict"] == "PASS" for c in out["checks"].values()), out["checks"]
    assert out["network_request"].startswith("NOT INDEPENDENTLY PROVEN")
    assert "tenant" in out["statement"] and "current security posture" in out["statement"]


def test_j_packaged_anchor_rejects_the_ephemeral_key(world):
    engine = verification.verify(_bytes(world["report"]))
    assert engine["authenticity"]["verdict"] == "UNKNOWN KEY"
    assert engine["operations"]["verdict"] == "NOT VERIFIED"
    assert engine["deployment_acknowledgment"]["verdict"] == "NOT VERIFIED"


def test_j_combined_scan_requires_sign(world):
    argv = [a for a in world["argv"] if a != "--sign"]
    proc = subprocess.run(argv, cwd=ROOT, env=world["env"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and not proc.stdout.strip()
    assert "requires --sign" in proc.stderr


def test_j_duplicate_challenge_kinds_are_refused(world):
    argv = world["argv"] + ["--deployment-challenge", "d" * 64]
    proc = subprocess.run(argv, cwd=ROOT, env=world["env"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2 and not proc.stdout.strip()
    assert "at most once" in proc.stderr


# ---- B, C, D, H: the policy gate reads authenticated coverage -------------------------

def test_b_form5_satisfies_full_authentication_and_dap_policy(world, tmp_path):
    out = _gate(world, tmp_path, _gate_report(world), _full_policy(world))
    assert out["verdict"] == "CLEAN" and out["check"] == "ALL", out


def test_b_form5_satisfies_a_form4_policy(world, tmp_path):
    policy = _policy(world, **{"min-sig-version": 4, "verified-authentication-required": True,
                               "declared-authentication-required": True,
                               "scope": {"operations": ["initialize"]}})
    out = _gate(world, tmp_path, _gate_report(world), policy)
    assert out["verdict"] == "CLEAN", out


def test_h_form4_authentication_assurance_still_passes(world, tmp_path):
    doc = _gate_report(world, sig_version=4, record=None)
    engine = verification.verify(_bytes(doc), anchor=world["anchor"])
    assert engine["operations"]["verdict"] == "VERIFIED"
    assert engine["deployment_acknowledgment"]["verdict"] == "NOT VERIFIED"
    policy = _policy(world, **{"min-sig-version": 4, "verified-authentication-required": True,
                               "scope": {"operations": ["initialize"]}})
    assert _gate(world, tmp_path, doc, policy)["verdict"] == "CLEAN"


def test_c_form5_without_assurance_is_never_clean(world, tmp_path):
    content = copy.deepcopy(world["report"]["content_observed"])
    del content["authentication_assurance"]
    out = _gate(world, tmp_path, _gate_report(world, content=content), _full_policy(world))
    assert out["verdict"] == "CONDITIONAL" and out["check"] == "AUTHENTICATION-ASSURANCE-MISSING", out


def test_c_form5_without_operations_is_never_clean(world, tmp_path):
    doc = _gate_report(world, content={})
    engine = verification.verify(_bytes(doc), anchor=world["anchor"])
    assert engine["authenticity"]["verdict"] == "SIGNED BY"
    assert engine["operations"]["verdict"] == "NOT VERIFIED"
    out = _gate(world, tmp_path, doc, _full_policy(world, **{"min-sig-version": 3}))
    assert out["verdict"] == "CONDITIONAL" and out["check"] == "AUTHENTICATION-ASSURANCE-MISSING", out
    # Form 5 without operations does not stand in for form 4.
    out = _gate(world, tmp_path, doc, _policy(world, **{"min-sig-version": 4}))
    assert out["verdict"] == "REJECT" and out["check"] == "SIG-VERSION", out
    # Nor does it prove scope operations.
    out = _gate(world, tmp_path, doc, _policy(world, scope={"operations": ["initialize"]}))
    assert out["verdict"] == "CONDITIONAL" and out["check"] == "SCOPE", out


def test_c_unsigned_assurance_beside_a_form5_signature_is_refused(world, tmp_path):
    content = {"authentication_assurance": copy.deepcopy(world["report"]["content_observed"]["authentication_assurance"])}
    doc = copy.deepcopy(_gate_report(world, content={}))
    doc["content_observed"] = content       # added after signing; form 5 signed content_observed as null
    engine = verification.verify(_bytes(doc), anchor=world["anchor"])
    assert engine["authenticity"]["verdict"] == "DIVERGENCE"
    assert engine["operations"]["verdict"] == "NOT VERIFIED"
    assert _gate(world, tmp_path, doc, _full_policy(world))["verdict"] == "REJECT"
    with pytest.raises(ValueError, match="content_observed"):
        rv.signed_content(doc, [])


def test_d_required_dap_missing_fails_closed(world, tmp_path):
    form4 = _gate_report(world, sig_version=4, record=None)
    out = _gate(world, tmp_path, form4, _full_policy(world, **{"min-sig-version": 4}))
    assert out["verdict"] == "REJECT" and out["check"] == "DEPLOYMENT-ACKNOWLEDGMENT", out


def test_d_dap_bound_to_another_reviewer_challenge_fails_closed(world, tmp_path):
    other = dap.create_challenge(world["target"], binding_scope="dedicated-host")
    out = _gate(world, tmp_path, _gate_report(world),
                _full_policy(world, **{"deployment-acknowledgment-challenge": other}))
    assert out["verdict"] == "REJECT" and out["check"] == "DEPLOYMENT-ACKNOWLEDGMENT", out


def test_d_signed_mismatch_observation_fails_closed(world, tmp_path, trusted):
    challenge = dap.create_challenge(world["target"], binding_scope="dedicated-host")
    world["state"].routes[PUBLICATION_PATH] = text_reply("e" * 64)
    try:
        record = dap.observe(challenge, requested_target=world["target"], allow_private=True)
    finally:
        world["state"].routes[PUBLICATION_PATH] = text_reply(world["challenge"]["nonce"])
    assert record["result"] == dap.MISMATCH
    doc = _gate_report(world, record=record)
    assert verification.verify(_bytes(doc), anchor=world["anchor"])["deployment_acknowledgment"]["verdict"] == "VERIFIED"
    out = _gate(world, tmp_path, doc, _full_policy(world, **{"deployment-acknowledgment-challenge": challenge}))
    assert out["verdict"] == "REJECT" and out["detail"].startswith("MISMATCH"), out


@pytest.mark.parametrize("policy_extra", [
    {"deployment-acknowledgment-required": "yes"},
    {"deployment-acknowledgment-challenge": None},
    {"deployment-acknowledgment-challenge": {"nonce": "a" * 64}},
])
def test_d_malformed_dap_policy_rejects(world, tmp_path, policy_extra):
    out = _gate(world, tmp_path, _gate_report(world), _full_policy(world, **policy_extra))
    assert out["verdict"] == "REJECT" and out["check"] == "DEPLOYMENT-ACKNOWLEDGMENT-POLICY-INVALID", out


def test_d_dap_challenge_without_requirement_rejects(world, tmp_path):
    out = _gate(world, tmp_path, _gate_report(world),
                _policy(world, **{"deployment-acknowledgment-challenge": world["challenge"]}))
    assert out["verdict"] == "REJECT" and out["check"] == "DEPLOYMENT-ACKNOWLEDGMENT-POLICY-INVALID", out


# ---- E, F, G: tampering and stripping after signing --------------------------------

def _rejected(world, tmp_path, doc, engine_verdicts=("SIGNATURE INVALID", "DIVERGENCE")):
    engine = verification.verify(_bytes(doc), anchor=world["anchor"])
    assert engine["authenticity"]["verdict"] in engine_verdicts, engine["authenticity"]
    assert engine["failed_stage"] == "authenticity"
    for name in ("operations", "deployment_acknowledgment"):
        assert engine[name]["verdict"] == "NOT VERIFIED"
    assert dap.verify_report(_bytes(doc), world["challenge"], anchor=world["anchor"])["verdict"] == dap.INVALID
    out = _gate(world, tmp_path, doc, _full_policy(world))
    assert out["verdict"] == "REJECT" and out["check"] == "SIGNATURE-INVALID", out


def test_e_altered_signed_operations_rejected(world, tmp_path):
    doc = copy.deepcopy(world["report"])
    ops = doc["content_observed"]["operations"]
    ops.append(next(o for o in rv.OPERATIONS if o not in ops))
    _rejected(world, tmp_path, doc)


def test_e_altered_signed_assurance_rejected(world, tmp_path):
    doc = copy.deepcopy(world["report"])
    doc["content_observed"]["authentication_assurance"]["deployment_challenge"] = "d" * 64
    _rejected(world, tmp_path, doc)


@pytest.mark.parametrize("path, value", [
    (("nonce",), "d" * 64),
    (("challenge", "nonce"), "d" * 64),
    (("challenge_id",), "0" * 64),
    (("challenge", "target"), "https://other.example/mcp"),
    (("requested_target",), "https://other.example/mcp"),
    (("result",), "MISMATCH"),
])
def test_f_altered_signed_dap_binding_rejected(world, tmp_path, path, value):
    doc = copy.deepcopy(world["report"])
    node = doc[rv.DEPLOYMENT_KEY]
    for step in path[:-1]:
        node = node[step]
    node[path[-1]] = value
    _rejected(world, tmp_path, doc)


def test_f_resigned_altered_nonce_still_fails_binding(world, tmp_path):
    record = copy.deepcopy(world["report"][rv.DEPLOYMENT_KEY])
    record["nonce"] = "d" * 64
    doc = _gate_report(world, record=record)
    assert verification.verify(_bytes(doc), anchor=world["anchor"])["authenticity"]["verdict"] == "SIGNED BY"
    assert dap.verify_report(_bytes(doc), world["challenge"], anchor=world["anchor"])["verdict"] == dap.INVALID
    out = _gate(world, tmp_path, doc, _full_policy(world))
    assert out["verdict"] == "REJECT" and out["check"] == "DEPLOYMENT-ACKNOWLEDGMENT", out


@pytest.mark.parametrize("strip", ["dap", "content", "assurance", "operations", "dap-downgrade-to-4"])
def test_g_removing_a_signed_component_rejected(world, tmp_path, strip):
    doc = copy.deepcopy(world["report"])
    if strip in ("dap", "dap-downgrade-to-4"):
        del doc[rv.DEPLOYMENT_KEY]
        if strip == "dap-downgrade-to-4":
            doc["sig_version"] = 4
    elif strip == "content":
        del doc["content_observed"]
    elif strip == "assurance":
        del doc["content_observed"]["authentication_assurance"]
    else:
        del doc["content_observed"]["operations"]
    _rejected(world, tmp_path, doc)


# ---- I: historical signature forms are byte-for-byte unchanged -----------------------

def _historical_payload():
    findings = [{"server_name": "s", "rule": "R-1", "vector_type": "v", "severity": "LOW",
                 "severity_basis": "b", "endpoint": "https://example.invalid/mcp", "description": "d",
                 "remediation": "r"}]
    payload = {"schema_version": 3, "hash_scheme": "verdict-v3", "target": "https://example.invalid/mcp",
               "status": "completed", "total_checks": 1, "findings_count": 1, "probe_set_version": "p",
               "coverage": {}, "severity_counts": rv.severity_counts(findings), "findings": findings,
               "evidence": {"scheme": rv.EVIDENCE_SCHEME_V1, "states": [{"access_class": "anonymous", "state_id": "a" * 64}]},
               "provenance": {"tool_version": "1.1.46", "tool_manifest": "b" * 64},
               "probes": [{"name": "P1", "status": "PASS"}],
               "content_observed": {"operations": ["initialize"], "session_established": True,
                                    "authentication_assurance": {"endpoint": "https://example.invalid/mcp"}}}
    return payload, findings


def _expected_bytes(form, payload, findings):
    """The documented layout of each historical form, built without signed_content."""
    graded = {k: payload[k] for k in ("target", "status", "total_checks", "findings_count",
                                      "probe_set_version", "coverage", "severity_counts")}
    graded["findings"] = [dict(f) for f in findings]
    if form == 1:
        body = graded
    elif form == 2:
        body = {"sig_version": 2, "evidence": payload["evidence"], "report": graded}
    else:
        body = {"sig_version": form, "evidence": payload["evidence"], "report": graded,
                "probes": payload["probes"], "provenance": payload["provenance"]}
        if form == 4:
            body["content_observed"] = payload["content_observed"]
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


@pytest.mark.parametrize("form", [1, 2, 3, 4])
def test_i_historical_forms_byte_for_byte(form):
    payload, findings = _historical_payload()
    if form < 4:
        del payload["content_observed"]
    if form < 3:
        del payload["provenance"], payload["probes"]
    if form < 2:
        del payload["evidence"]
    payload["sig_version"] = form
    assert rv.signed_content(payload, findings) == _expected_bytes(form, payload, findings)
    # sig_version absent is form 1
    if form == 1:
        del payload["sig_version"]
        assert rv.signed_content(payload, findings) == _expected_bytes(1, payload, findings)


@pytest.mark.parametrize("relpath, form", [
    ("tests/fixtures/published/tollbooth-baseline.json", 3),
    ("client/public/tollbooth-2026-11-25.json", 4),
])
def test_i_production_signed_reports_still_verify(relpath, form):
    path = ROOT / relpath
    if not path.exists():
        pytest.skip("published report not in this checkout")
    raw = path.read_bytes()
    doc = json.loads(raw)
    assert doc["sig_version"] == form
    engine = verification.verify(raw)       # packaged pinned key history; production key untouched
    assert engine["failed_stage"] is None
    assert engine["integrity"]["verdict"] == "INTACT"
    assert engine["authenticity"]["verdict"] == "SIGNED BY"
    assert engine["operations"]["verdict"] == ("VERIFIED" if form == 4 else "NOT VERIFIED")
    assert engine["deployment_acknowledgment"]["verdict"] == "NOT VERIFIED"
