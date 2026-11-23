"""mcp_authscan.verification: the single offline verdict engine.

Covers the acceptance items for PR #58:
- fixed failure order catalog -> format -> integrity -> authenticity;
- status-flip negative: report_hash, findings and signature unchanged, one probe status flipped.
  sig_version 3/4: integrity INTACT, authenticity rejected with a specific reason.
  sig_version 1/2: the signature still verifies, and probe statuses are explicitly NOT VERIFIED;
- pinned key history: tampering fails closed, a withdrawn key rejects every signature, no date
  in a report is ever used to choose a key;
- deterministic: no clock, socket or environment variable is read; same input, same output;
- every front end (CLI, report_verify adapters, gate, web adapter) agrees with the engine.
"""
import copy
import datetime
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import policy_check, verify
from mcp_authscan import report_verify as rv
from mcp_authscan import verification as V
from mcp_authscan.monolith import PROBE_SET_VERSION
from mcp_authscan.report_signing import sign_statement

ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026.11.19.3"
PUBLISHED_KEY_ID = "9b79936f975f9770b3840dbd45f93d2bb23d1bd2cc3d7d81d092e5cd41926e9d"
WITHDRAWN_KEY_ID = "ed25519-1ed8ee728c587846"


def _public(key):
    import base64
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _report(sig_version=None, stamp=STAMP):
    findings = [{"server_name": "s", "rule": "CORS-2", "vector_type": "cors", "severity": "MEDIUM",
                 "severity_basis": "observed", "endpoint": "/token", "description": "d", "remediation": "r"}]
    p = {
        "target": "https://synthetic.invalid/mcp", "status": "completed", "total_checks": 3,
        "findings_count": 1, "probe_set_version": stamp, "coverage": 1.0,
        "severity_counts": rv.severity_counts(findings), "findings": findings,
        "hash_scheme": rv.HASH_SCHEME, "schema_version": rv.SCHEMA_VERSION,
        "run_started_at": "2026-11-17T00:00:00+00:00",
        "probes": [{"name": "issuer-identity", "status": "PASS"},
                   {"name": "token-cors", "status": "FAIL"},
                   {"name": "pkce-s256", "status": "PASS"}],
    }
    if sig_version is not None:
        p["sig_version"] = sig_version
    if sig_version in (2, 3, 4):
        p["evidence"] = {"scheme": "evidence-binding-v1",
                         "states": [{"access_class": "anonymous", "state_id": "a" * 64}]}
    if sig_version in (3, 4):
        p["provenance"] = {"tool_version": "1.1.35", "tool_manifest": "b" * 64}
    if sig_version == 4:
        p["content_observed"] = {"operations": ["initialize", "tools/list"], "session_established": True}
    p["report_hash"] = rv.compute(p, findings)[0]
    return p


def _sign(p, key):
    p = copy.deepcopy(p)
    signature = sign_statement(key, rv.signed_content(p, p["findings"]))
    p["key_id"], p["signature"] = signature["key_id"], signature
    return p


def _anchor(key, status="active"):
    sig = sign_statement(key, b"x")
    return {"source": "test", "sha256": None, "keys": [{
        "key_id": sig["key_id"], "alg": "ed25519", "public_key": _public(key), "status": status,
        "withdrawn_commit": None if status == "active" else "0" * 40}]}


def _flip(p, name="token-cors", to="PASS"):
    flipped = copy.deepcopy(p)
    for probe in flipped["probes"]:
        if probe["name"] == name:
            probe["status"] = to
    return flipped


def _run(p, **kw):
    return V.verify(json.dumps(p), **kw)


# ---- fixed order ------------------------------------------------------------------------

def test_failure_order_is_catalog_format_integrity_authenticity(tmp_path):
    key = Ed25519PrivateKey.generate()
    good = _sign(_report(3), key)
    broken_signature = copy.deepcopy(good)
    broken_signature["signature"]["value"] = "A" * 86   # 64 zero-ish bytes, wrong signature
    altered = dict(broken_signature, total_checks=99)
    unknown_stamp = dict(altered, probe_set_version="no-such-probe-set")
    catalog = tmp_path / "catalog.json"
    catalog.write_bytes(V.catalog_path().read_bytes().replace(b'"2026.11.19.3"', b'"2026.11.19.8"'))

    r = _run(unknown_stamp, anchor=_anchor(key), catalog_file=catalog)
    assert r["failed_stage"] == "catalog"
    assert [r[s]["verdict"] for s in ("format", "integrity", "authenticity")] == [V.NOT_CHECKED] * 3

    r = _run(unknown_stamp, anchor=_anchor(key))
    assert r["failed_stage"] == "format" and r["format"]["verdict"] == "UNKNOWN PROBE SET"
    assert r["integrity"]["verdict"] == V.NOT_CHECKED == r["authenticity"]["verdict"]

    r = _run(altered, anchor=_anchor(key))
    assert r["failed_stage"] == "integrity" and r["integrity"]["verdict"] == "ALTERED"
    # Integrity and authenticity are independent once the format is readable; both are reported.
    assert r["authenticity"]["verdict"] == "SIGNATURE INVALID"

    r = _run(broken_signature, anchor=_anchor(key))
    assert r["failed_stage"] == "authenticity" and r["integrity"]["verdict"] == "INTACT"

    r = _run(good, anchor=_anchor(key))
    assert r["failed_stage"] is None and r["authenticity"]["verdict"] == "SIGNED BY"
    assert r["stages"] == ["catalog", "format", "integrity", "authenticity"]


def test_catalog_pin_is_attested_in_every_result():
    r = _run(_report())
    assert r["catalog"] == {"verdict": "PINNED", "sha256": V.CATALOG_SHA256,
                            "stamp_in_catalog": True, "attestation": "IN CATALOG"}
    assert hashlib.sha256(V.catalog_path().read_bytes()).hexdigest() == V.CATALOG_SHA256
    assert _run(_report(stamp="1.1.0"))["catalog"]["attestation"].startswith("RELEASES ONLY")
    web = _run(_report(stamp="web-source-sha256:" + "c" * 64))
    assert web["catalog"]["stamp_in_catalog"] is False and web["catalog"]["attestation"].startswith("WEB SOURCE DIGEST")


# ---- status-flip negative -------------------------------------------------------------------

@pytest.mark.parametrize("sig_version", [3, 4])
def test_status_flip_with_probe_covering_signature_is_rejected(sig_version):
    key = Ed25519PrivateKey.generate()
    signed = _sign(_report(sig_version), key)
    flipped = _flip(signed)
    # The flip leaves report_hash, findings and the signature byte-identical.
    for field in ("report_hash", "findings", "signature", "key_id"):
        assert json.dumps(flipped[field], sort_keys=True) == json.dumps(signed[field], sort_keys=True)
    assert flipped["probes"] != signed["probes"]

    before = _run(signed, anchor=_anchor(key))
    assert before["authenticity"]["verdict"] == "SIGNED BY" and before["probe_statuses"]["verdict"] == "VERIFIED"

    after = _run(flipped, anchor=_anchor(key))
    assert after["integrity"]["verdict"] == "INTACT"           # graded hash intact
    assert after["authenticity"]["verdict"] == "SIGNATURE INVALID"
    assert after["failed_stage"] == "authenticity"
    reason = after["authenticity"]["reason"]
    assert "report_hash is intact" in reason and "probes" in reason and f"sig_version {sig_version}" in reason
    assert after["probe_statuses"]["verdict"] == "NOT VERIFIED"


@pytest.mark.parametrize("sig_version", [None, 1, 2])
def test_status_flip_under_legacy_signature_says_probe_status_not_verified(sig_version):
    key = Ed25519PrivateKey.generate()
    signed = _sign(_report(sig_version), key)
    flipped = _flip(signed)
    for field in ("report_hash", "findings", "signature"):
        assert flipped[field] == signed[field]
    for payload in (signed, flipped):
        r = _run(payload, anchor=_anchor(key))
        # The older signature form does not cover probes, so the flip is invisible to it...
        assert r["integrity"]["verdict"] == "INTACT" and r["authenticity"]["verdict"] == "SIGNED BY"
        assert "probes" not in r["authenticity"]["covers"]
        # ...and the engine says so explicitly instead of calling the statuses authentic.
        assert r["probe_statuses"]["verdict"] == "NOT VERIFIED"
        assert "does not cover probes" in r["probe_statuses"]["reason"]


def test_status_flip_surfaces_in_every_front_end(tmp_path):
    key = Ed25519PrivateKey.generate()
    anchor_file = tmp_path / "keys.json"
    anchor_file.write_text(json.dumps({"keys": [{"key_id": sign_statement(key, b"x")["key_id"],
                                                 "alg": "ed25519", "public_key": _public(key)}]}))
    flipped = tmp_path / "flipped.json"
    flipped.write_text(json.dumps(_flip(_sign(_report(3), key))))
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps(_flip(_sign(_report(1), key))))

    assert verify.main(["--keys", str(anchor_file), str(flipped)]) == 1
    # CLI: authenticity rejected; legacy form passes but names probe statuses NOT VERIFIED.
    assert verify.main(["--keys", str(anchor_file), str(legacy)]) == 0
    assert rv.authenticity(json.loads(flipped.read_text()), json.loads(anchor_file.read_text())["keys"]) == "SIGNATURE INVALID"
    assert rv.verify(str(flipped))[0] == "MATCH"   # graded hash intact


def test_status_flip_cli_output(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    anchor_file = tmp_path / "keys.json"
    anchor_file.write_text(json.dumps([{"key_id": sign_statement(key, b"x")["key_id"],
                                        "alg": "ed25519", "public_key": _public(key)}]))
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_flip(_sign(_report(4), key))))
    assert verify.main(["--keys", str(anchor_file), str(path)]) == 1
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "AUTHENTICITY" and out[1].startswith("SIGNATURE INVALID: ")
    assert "PROBE_STATUSES=NOT VERIFIED" in "\n".join(out)
    path.write_text(json.dumps(_flip(_sign(_report(2), key))))
    assert verify.main(["--keys", str(anchor_file), str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "MATCH"
    assert any(line.startswith("PROBE_STATUSES=NOT VERIFIED (sig_version 2 does not cover probes") for line in out)


def test_gate_rejects_status_flip_under_default_sig_version_floor(tmp_path):
    key = Ed25519PrivateKey.generate()
    key_id = sign_statement(key, b"x")["key_id"]
    keys = [{"key_id": key_id, "alg": "ed25519", "public_key": _public(key)}]
    policy = {"trusted-signers": [key_id], "required-probes": ["issuer-identity", "token-cors", "pkce-s256"],
              "min-sig-version": 3}
    pol = tmp_path / "policy.json"
    pol.write_text(json.dumps(policy))
    for sig_version, check in ((3, "SIGNATURE-INVALID"), (1, "SIG-VERSION")):
        path = tmp_path / f"flip{sig_version}.json"
        path.write_text(json.dumps(_flip(_sign(_report(sig_version), key))))
        result = policy_check.evaluate(str(path), str(pol), keys)
        assert result["verdict"] == "REJECT" and result["check"] == check, result


# ---- pinned key history -------------------------------------------------------------------

def test_packaged_key_history_is_pinned_and_matches_published_keys():
    raw = V.key_history_path().read_bytes()
    assert hashlib.sha256(raw).hexdigest() == V.KEY_HISTORY_SHA256
    anchor = V.packaged_anchor()
    assert anchor["source"] == "packaged" and anchor["sha256"] == V.KEY_HISTORY_SHA256
    statuses = {k["key_id"]: k["status"] for k in anchor["keys"]}
    assert statuses == {WITHDRAWN_KEY_ID: "withdrawn", PUBLISHED_KEY_ID: "active"}
    published = V.published_keys(anchor)
    assert published == json.loads((ROOT / "client/public/keys.json").read_text())
    assert published["keys"] == json.loads((ROOT / "mcp_authscan/keys-default.json").read_text())


def test_tampered_key_history_fails_closed(tmp_path):
    tampered = tmp_path / "key_history.json"
    tampered.write_bytes(V.key_history_path().read_bytes().replace(b'"withdrawn",', b'"active",', 1))
    p = _report(3)
    p["signature"] = {"alg": "ed25519", "key_id": WITHDRAWN_KEY_ID, "value": "A" * 86}
    r = _run(p, key_history_file=tampered)
    assert r["authenticity"]["verdict"] == "UNAVAILABLE" and "digest mismatch" in r["authenticity"]["reason"]
    assert r["failed_stage"] == "authenticity" and r["trust_anchor"]["source"] is None


def test_withdrawn_key_rejects_every_signature_whatever_the_report_date():
    p = _report(3)
    p["signature"] = {"alg": "ed25519", "key_id": WITHDRAWN_KEY_ID, "value": "A" * 86}
    results = []
    for started in ("2026-11-17T23:20:00+00:00", "2020-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00"):
        p["run_started_at"] = started   # unsigned: must never influence key selection
        results.append(_run(p))
    assert all(r["authenticity"]["verdict"] == "KEY NOT VALID" for r in results)
    assert len({json.dumps(r, sort_keys=True) for r in results}) == 1
    assert "eef3a859f49afc08505fce9a9112a0eda85f6997" in results[0]["authenticity"]["reason"]


def test_withdrawn_key_is_rejected_even_with_a_cryptographically_valid_signature():
    key = Ed25519PrivateKey.generate()
    signed = _sign(_report(3), key)
    assert _run(signed, anchor=_anchor(key))["authenticity"]["verdict"] == "SIGNED BY"
    assert _run(signed, anchor=_anchor(key, status="withdrawn"))["authenticity"]["verdict"] == "KEY NOT VALID"
    assert _run(signed, anchor=_anchor(key, status="revoked"))["authenticity"]["verdict"] == "KEY NOT VALID"


def test_external_anchor_accepts_history_or_published_list_and_reports_its_digest(tmp_path):
    key = Ed25519PrivateKey.generate()
    signed = _sign(_report(3), key)
    entry = {"key_id": signed["key_id"], "alg": "ed25519", "public_key": _public(key)}
    listed = tmp_path / "list.json"
    listed.write_text(json.dumps({"keys": [entry]}))
    history = tmp_path / "history.json"
    history.write_text(json.dumps({"schema": "key-history-v1", "keys": [dict(entry, status="withdrawn")]}))
    a = V.external_anchor(listed)
    assert a["sha256"] == hashlib.sha256(listed.read_bytes()).hexdigest()
    assert _run(signed, anchor=a)["authenticity"]["verdict"] == "SIGNED BY"
    assert _run(signed, anchor=V.external_anchor(history))["authenticity"]["verdict"] == "KEY NOT VALID"
    for bad in ([{"key_id": "../x", "alg": "ed25519", "public_key": entry["public_key"]}],
                [dict(entry, alg="rsa")], [entry, entry], {"schema": "key-history-v1", "keys": [dict(entry, status="??")]}):
        (tmp_path / "bad.json").write_text(json.dumps(bad))
        with pytest.raises(V.AnchorError):
            V.external_anchor(tmp_path / "bad.json")


# ---- deterministic: no clock, socket or environment -------------------------------------------

def _forbid(*_a, **_k):
    raise AssertionError("verification must not read the clock or open a socket")


def test_engine_reads_no_clock_socket_or_environment(monkeypatch):
    key = Ed25519PrivateKey.generate()
    cases = [_report(), dict(_report(), total_checks=7), _sign(_report(4), key), _flip(_sign(_report(3), key))]
    baseline = [_run(c, anchor=_anchor(key)) for c in cases]
    for name in ("time", "time_ns", "monotonic", "perf_counter", "localtime", "gmtime"):
        monkeypatch.setattr(time, name, _forbid)

    class FrozenDatetime(datetime.datetime):
        @classmethod
        def now(cls, tz=None):
            _forbid()

        @classmethod
        def utcnow(cls):
            _forbid()
    monkeypatch.setattr(datetime, "datetime", FrozenDatetime)
    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, _forbid)
    monkeypatch.setattr(os, "environ", {})
    monkeypatch.setattr(os, "getenv", _forbid)
    assert [_run(c, anchor=_anchor(key)) for c in cases] == baseline


def test_same_report_same_result_regardless_of_key_order():
    p = _report(4)
    forward = json.dumps(p)
    backward = json.dumps(dict(reversed(list(p.items()))))
    assert V.verify(forward) == V.verify(forward) == V.verify(backward)


# ---- every front end agrees with the engine ---------------------------------------------------

def test_web_adapter_prints_the_engine_result():
    p = _report(3)
    p["signature"] = {"alg": "ed25519", "key_id": PUBLISHED_KEY_ID, "value": "A" * 86}
    proc = subprocess.run([sys.executable, "-m", "mcp_authscan.verify_upload"], input=json.dumps(p),
                          capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == _run(p)


def test_cli_json_output_is_the_engine_result(tmp_path, capsys):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_report(stamp=PROBE_SET_VERSION)))
    assert verify.main(["--json", str(path)]) == 0
    assert json.loads(capsys.readouterr().out) == V.verify(path.read_bytes())


def test_cli_require_signature_rejects_unsigned(tmp_path, capsys):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_report()))
    assert verify.main([str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0] == "MATCH" and "AUTHENTICITY=NOT SIGNED" in out
    assert verify.main(["--require-signature", str(path)]) == 1
    assert capsys.readouterr().out.splitlines()[0] == "AUTHENTICITY"


# ---- the published signature path: a real report signed by the published key ------------------

PUBLISHED_REPORT = ROOT / "tests/fixtures/published/tollbooth-baseline.json"


def test_published_report_verifies_against_the_packaged_key_history():
    raw = PUBLISHED_REPORT.read_bytes()
    assert raw == (ROOT / "client/public/tollbooth-authority-2026-11-21.json").read_bytes()
    r = V.verify(raw)   # packaged anchor: no test key involved
    assert r["failed_stage"] is None
    assert r["catalog"]["attestation"] == "IN CATALOG"
    assert r["integrity"]["verdict"] == "INTACT"
    assert (r["authenticity"]["verdict"], r["authenticity"]["key_id"]) == ("SIGNED BY", PUBLISHED_KEY_ID)
    assert r["authenticity"]["sig_version"] == 3 and r["probe_statuses"]["verdict"] == "VERIFIED"
    assert r["trust_anchor"] == {"source": "packaged", "sha256": V.KEY_HISTORY_SHA256}


def test_status_flip_on_the_published_report_is_rejected_everywhere(tmp_path, capsys):
    report = json.loads(PUBLISHED_REPORT.read_text())
    flipped = copy.deepcopy(report)
    [probe] = [p for p in flipped["probes"] if p["name"] == "token-cors"]
    assert probe["status"] == "NOT_OBSERVED"
    probe["status"] = "PASS"
    for field in ("report_hash", "findings", "signature", "key_id", "sig_version"):
        assert flipped[field] == report[field]
    path = tmp_path / "flipped.json"
    path.write_text(json.dumps(flipped))

    r = V.verify(path.read_bytes())
    assert r["integrity"]["verdict"] == "INTACT"
    assert r["authenticity"]["verdict"] == "SIGNATURE INVALID" and r["failed_stage"] == "authenticity"
    assert "probes" in r["authenticity"]["reason"] and r["probe_statuses"]["verdict"] == "NOT VERIFIED"

    assert verify.main([str(path)]) == 1
    assert capsys.readouterr().out.splitlines()[0] == "AUTHENTICITY"
    assert rv.verify(str(path))[0] == "MATCH"          # report_hash alone cannot see it

    from importlib.resources import files
    pkg = files("mcp_authscan")
    original = policy_check.evaluate(str(PUBLISHED_REPORT), str(pkg / "policy-default.json"), str(pkg / "keys-default.json"))
    assert original["verdict"] != "REJECT" or original["check"] != "SIGNATURE-INVALID"
    gate = policy_check.evaluate(str(path), str(pkg / "policy-default.json"), str(pkg / "keys-default.json"))
    assert (gate["verdict"], gate["check"]) == ("REJECT", "SIGNATURE-INVALID")
