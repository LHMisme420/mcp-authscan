"""Real Ed25519 end-to-end tests for `mcp-authscan assurance`.

Reports are signed with an ephemeral key generated here and verified by the
unmocked engine in a subprocess; the public key reaches it only via --trust-anchor.
No production key material is read.
"""
import base64
import copy
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ed25519 = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.ed25519")

from mcp_authscan import report_verify as rv  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TARGET = "https://example.test/mcp"
KEY_ID = "ephemeral-test"


def b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@pytest.fixture
def key():
    return ed25519.Ed25519PrivateKey.generate()


def anchor_file(tmp_path, private_key):
    public = private_key.public_key().public_bytes_raw()
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"keys": [{"key_id": KEY_ID, "alg": "ed25519", "public_key": b64url(public)}]}))
    return path


def probe(probe_id, name, status):
    return {"probe_id": probe_id, "name": name, "status": status, "http_status": 200,
            "prerequisite_met": True, "limitation": None, "severity": "HIGH",
            "body_sha256": hashlib.sha256(f"{name}:{status}".encode()).hexdigest()}


def report(issuer_status):
    return {
        "schema_version": rv.SCHEMA_VERSION, "hash_scheme": rv.HASH_SCHEME_V4,
        "target": TARGET, "status": "complete", "total_checks": 2, "findings_count": 0,
        "probe_set_version": "2026.10.30.1", "coverage": "full",
        "severity_counts": rv.severity_counts([]), "findings": [],
        "probes": [probe(1, "issuer-identity", issuer_status), probe(2, "token-audience", "PASS")],
        "evidence_hash_scheme": rv.EVIDENCE_HASH_SCHEME,
        "evidence": {"scheme": rv.EVIDENCE_SCHEME_V1, "states": []},
        "provenance": {"tool_version": "0.0.0-test", "tool_manifest": "0" * 64},
        rv.SIG_VERSION_KEY: rv.SIG_VERSION_PROVENANCE,
    }


def sign(doc, private_key):
    doc = copy.deepcopy(doc)
    doc.pop("signature", None)
    doc["report_hash"] = rv.compute({k: v for k, v in doc.items() if k != "report_hash"}, doc["findings"])[0]
    doc["evidence_hash"] = rv.evidence_hash(doc["probes"])
    value = private_key.sign(rv.signed_content(doc, doc["findings"]))
    doc["signature"] = {"alg": "ed25519", "key_id": KEY_ID, "value": b64url(value)}
    return doc


def run_assurance(tmp_path, docs, *, anchor=None, observed=None):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    paths, observations = [], []
    for i, doc in enumerate(docs):
        data = json.dumps(doc, sort_keys=True).encode() if isinstance(doc, dict) else doc
        path = tmp_path / f"report{i}.json"
        path.write_bytes(data)
        paths.append(path)
        when = now - timedelta(hours=len(docs) - i)
        observations.append({"file_sha256": hashlib.sha256(data).hexdigest(),
                             "observed_at": when.isoformat().replace("+00:00", "Z")})
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"target": TARGET, "max_age_days": 3,
                                  "required_probe_classes": {"authserver": ["issuer-identity"]},
                                  "observations": observed or observations}))
    artifact = tmp_path / "verdict.json"
    cmd = [sys.executable, "-m", "mcp_authscan.cli_wrapper", "assurance",
           "--policy", str(policy), "--artifact", str(artifact)]
    for path in paths:
        cmd += ["--report", str(path)]
    if anchor is not None:
        cmd += ["--trust-anchor", str(anchor)]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=120)
    result = json.loads(artifact.read_text())
    assert proc.stdout.startswith(result["verdict"] + " "), (proc.stdout, proc.stderr)
    assert proc.returncode == (0 if result["verdict"] == "CURRENT" else 1), (proc.returncode, proc.stderr)
    return result


def row(label, result):
    print(f"\n{label:22} | {result['verdict']:12} | {result['reason']}")


def test_signed_status_change_is_regressed(tmp_path, key):
    prior, latest = sign(report("PASS"), key), sign(report("FAIL"), key)
    assert prior["report_hash"] != latest["report_hash"]
    anchor = anchor_file(tmp_path, key)
    # Each signed report verifies on its own, so the verdict below comes from the status change.
    assert run_assurance(tmp_path, [prior], anchor=anchor)["verdict"] == "CURRENT"
    result = run_assurance(tmp_path, [prior, latest], anchor=anchor)
    row("SIGNED STATUS CHANGE", result)
    assert result["verdict"] == "REGRESSED", result
    assert (result["prior_report_hash"], result["latest_report_hash"]) == (prior["report_hash"], latest["report_hash"])


def test_tampered_signed_report_is_inconclusive(tmp_path, key):
    tampered = sign(report("PASS"), key)
    # provenance is inside the sig_version 3 signature and outside report_hash, so
    # integrity stays INTACT and only the Ed25519 check can catch this.
    tampered["provenance"]["tool_version"] = "9.9.9-forged"
    result = run_assurance(tmp_path, [tampered], anchor=anchor_file(tmp_path, key))
    row("TAMPERED SIGNED REPORT", result)
    assert result["verdict"] == "INCONCLUSIVE", result
    assert result["reason"] == "report signature not verified", result


def test_unsigned_report_is_inconclusive(tmp_path, key):
    unsigned = sign(report("PASS"), key)
    del unsigned["signature"]
    result = run_assurance(tmp_path, [unsigned], anchor=anchor_file(tmp_path, key))
    row("UNSIGNED REPORT", result)
    assert result["verdict"] == "INCONCLUSIVE", result
    assert result["reason"] == "report signature not verified", result


def test_default_packaged_anchor_rejects_ephemeral_key(tmp_path, key):
    result = run_assurance(tmp_path, [sign(report("PASS"), key)])
    assert result["verdict"] == "INCONCLUSIVE", result
    assert result["reason"] == "report signature not verified", result


@pytest.mark.parametrize("content", [b"not json", b"{}", b'{"keys": [{"key_id": "x", "alg": "rsa"}]}'])
def test_invalid_trust_anchor_fails_closed(tmp_path, key, content):
    bad = tmp_path / "bad-anchor.json"
    bad.write_bytes(content)
    result = run_assurance(tmp_path, [sign(report("PASS"), key)], anchor=bad)
    assert result["verdict"] == "INCONCLUSIVE", result
    assert result["reason"].startswith("trust anchor invalid"), result
