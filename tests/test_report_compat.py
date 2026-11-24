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


def test_schema3_report_verify_matches():
    assert rv.verify(str(FIX / SIGNED))[0] == "MATCH"


@pytest.mark.parametrize("name", LEGACY)
def test_legacy_report_matches_under_a_distinct_word(name):
    # Never plain MATCH: a 1.1.24 report must not read like a schema-3 one.
    assert rv.verify(str(FIX / name))[0] == "LEGACY_MATCH"


@pytest.mark.parametrize("name", LEGACY)
def test_pre_schema3_report_reads_as_it_did_in_1_1_24(name):
    report = _load(name)
    assert "schema_version" not in report and report["hash_scheme"] == "verdict-v3"
    result = verify_text(json.dumps(report))
    assert result["verdict"] == "INTACT"
    assert result["canonical_bytes"] is None          # never signed, so can never read as signed
    assert "LEGACY: pre-schema-3 report" in result["reason"] and "unsigned" in result["reason"]


@pytest.mark.parametrize("name", LEGACY)
def test_pre_schema3_tamper_is_caught(name, tmp_path):
    report = _load(name)
    report["exit_code"] = 99                           # a field the 1.1.24 hash covers
    (tmp_path / "t.json").write_text(json.dumps(report))
    assert rv.verify(str(tmp_path / "t.json"))[0] == "LEGACY_MISMATCH"
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


def _keys(tmp_path):
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps([json.loads((FIX / "signed-schema3-main-1a7d08c.pubkey.json").read_text())]))
    return str(keys)


def _lines(capsys):
    return {next(p for p in line.split() if p.endswith(".json")).rsplit("/", 1)[-1]: line
            for line in capsys.readouterr().out.splitlines()}


def test_cli_legacy_and_signed_never_print_the_same_words(tmp_path, capsys):
    assert rv.main(["--keys", _keys(tmp_path)] + [str(FIX / n) for n in LEGACY + [SIGNED]]) != 0  # D1: legacy reports are unsigned -> nonzero
    lines = _lines(capsys)
    for name in LEGACY:
        assert lines[name].startswith("LEGACY MATCH ")
        assert "UNSIGNED (pre-1.1.25 algorithm, releases 1.1.21-1.1.24)" in lines[name]
        assert "SIGNED BY" not in lines[name]
    assert lines[SIGNED].startswith("MATCH ") and " SIGNED BY " in lines[SIGNED]


def test_cli_without_keys_does_not_claim_signed(capsys):
    assert rv.main([str(FIX / SIGNED)]) != 0          # D1: no --keys -> signature unverified -> nonzero
    line = capsys.readouterr().out
    assert "SIGNATURE NOT CHECKED" in line and "SIGNED BY" not in line


def test_cli_bad_signature_fails(tmp_path, capsys):
    report = _load(SIGNED)
    report["signature"]["value"] = "A" + report["signature"]["value"][1:]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(report))
    assert rv.main(["--keys", _keys(tmp_path), str(bad)]) == 1
    assert "SIGNATURE INVALID" in capsys.readouterr().out
