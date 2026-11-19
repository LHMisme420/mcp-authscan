"""Reports from earlier releases must still open and verify, unchanged.

Fixtures are real reports, not hand-built ones:
- live-1.1.24.json, source-1.1.24.json: produced by mcp-authscan 1.1.24 installed
  from PyPI (pre-schema-3 format: verdict-v3, no schema_version, never signed);
- signed-schema3-main-1a7d08c.json: schema 3, signed, produced by main at 1a7d08c
  (before sig_version and evidence existed), with its public key alongside.
"""
import base64
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from mcp_authscan import report_verify as rv
from mcp_authscan.verify_upload import verify_text

FIX = Path(__file__).resolve().parent / "fixtures" / "compat"
LEGACY = ["live-1.1.24.json", "source-1.1.24.json"]
SIGNED = "signed-schema3-main-1a7d08c.json"


def _load(name):
    return json.loads((FIX / name).read_text())


@pytest.mark.parametrize("name", LEGACY + [SIGNED])
def test_report_verify_matches(name):
    assert rv.verify(str(FIX / name))[0] == "MATCH"


@pytest.mark.parametrize("name", LEGACY)
def test_pre_schema3_report_reads_as_it_did_in_1_1_24(name):
    report = _load(name)
    assert "schema_version" not in report and report["hash_scheme"] == "verdict-v3"
    result = verify_text(json.dumps(report))
    assert result["verdict"] == "INTACT"
    assert result["canonical_bytes"] is None          # never signed, so can never read as signed
    assert "Pre-schema-3 report" in result["reason"]


@pytest.mark.parametrize("name", LEGACY)
def test_pre_schema3_tamper_is_caught(name, tmp_path):
    report = _load(name)
    report["exit_code"] = 99                           # a field the 1.1.24 hash covers
    (tmp_path / "t.json").write_text(json.dumps(report))
    assert rv.verify(str(tmp_path / "t.json"))[0] == "MISMATCH"
    assert verify_text(json.dumps(report))["verdict"] == "ALTERED"


def test_pre_schema3_report_with_a_signature_cannot_authenticate():
    report = _load(LEGACY[0])
    report["signature"] = {"alg": "ed25519", "key_id": "a" * 64, "value": "AAAA"}
    result = verify_text(json.dumps(report))
    assert result["verdict"] == "INTACT" and result["canonical_bytes"] is None


def test_schema3_report_never_takes_the_legacy_path():
    report = _load(SIGNED)
    assert report["schema_version"] == 3 and not rv.is_legacy(report)
    stripped = copy.deepcopy(report)
    del stripped["schema_version"]                     # forced onto the legacy path
    result = verify_text(json.dumps(stripped))
    assert result["verdict"] != "INTACT"               # its hash is not a 1.1.24 hash
    assert result["canonical_bytes"] is None           # and it can no longer authenticate


def test_signed_schema3_from_main_still_verifies_and_authenticates():
    report = _load(SIGNED)
    key = json.loads((FIX / "signed-schema3-main-1a7d08c.pubkey.json").read_text())
    assert "sig_version" not in report and "evidence" not in report     # the pre-sig_version form
    result = verify_text(json.dumps(report))
    assert result["verdict"] == "INTACT"
    raw = base64.urlsafe_b64decode(key["public_key"] + "==")
    sig = base64.urlsafe_b64decode(report["signature"]["value"] + "==")
    Ed25519PublicKey.from_public_bytes(raw).verify(sig, base64.b64decode(result["canonical_bytes"]))
    tampered = copy.deepcopy(report)
    tampered["target"] = tampered["target"] + "x"     # a hashed field; report stays well formed
    assert verify_text(json.dumps(tampered))["verdict"] == "ALTERED"


def test_cli_verifier(tmp_path, capsys):
    assert rv.main([str(FIX / n) for n in LEGACY + [SIGNED]]) == 0
    assert capsys.readouterr().out.count("MATCH") == 3
