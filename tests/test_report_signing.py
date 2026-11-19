"""Signing tests use disposable test-owned keys, never the runner's default key."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import report_verify as rv
from mcp_authscan.report_signing import sign_report


def report():
    return {
        "schema_version": 3, "hash_scheme": "verdict-v3",
        "target": "https://synthetic.example.invalid/mcp", "status": "completed",
        "total_checks": 1, "findings_count": 0, "findings": [],
        "probe_set_version": "synthetic-test", "coverage": 1.0,
        "severity_counts": rv.severity_counts([]), "started_at": "not covered",
    }


@pytest.fixture
def signing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HOME", str(tmp_path))
    path = tmp_path / ".config/mcp-authscan/report-signing.pem"
    path.parent.mkdir(parents=True)
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    path.chmod(0o600)
    return key


def test_identical_bytes_hash_signature_and_timestamp_exclusion(signing_key):
    original = report()
    with patch.object(rv, "serialize", wraps=rv.serialize) as serializer:
        digest, covered, content = rv.compute(original, [], include_bytes=True)
        # No findings to sort: exactly one canonical-report serialization.
        assert serializer.call_count == 1
    assert content == rv.serialize(rv.canonical_report(original, []))
    assert digest == hashlib.sha256(content).hexdigest()
    original["report_hash"] = digest
    assert sign_report(original, content)
    public = signing_key.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert original["key_id"] == hashlib.sha256(raw).hexdigest()
    assert original["signature"]["key_id"] == original["key_id"]
    assert original["signature"]["alg"] == "ed25519"
    signature = original["signature"]["value"]
    public.verify(base64.urlsafe_b64decode(signature + "=="), content)
    assert rv.compute(original, []) == (digest, covered)
    changed = deepcopy(original)
    for field in ("started_at", "completed_at", "created_at", "attested_at", "session_id"):
        changed[field] = "different"
    assert rv.compute(changed, [], include_bytes=True)[2] == content
    changed["target"] = "https://changed.example.invalid/mcp"
    with pytest.raises(InvalidSignature):
        public.verify(base64.urlsafe_b64decode(signature + "=="),
                      rv.compute(changed, [], include_bytes=True)[2])


def test_missing_key_one_warning_unchanged_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    value = report()
    before = deepcopy(value)
    assert not sign_report(value, rv.compute(value, [], include_bytes=True)[2])
    assert value == before
    assert capsys.readouterr().err.count("Report unsigned:") == 1


def test_invalid_key_does_not_disclose_contents(signing_key, capsys):
    (Path.home() / ".config/mcp-authscan/report-signing.pem").write_text("PRIVATE TEST CONTENT")
    value = report()
    assert not sign_report(value, rv.compute(value, [], include_bytes=True)[2])
    error = capsys.readouterr().err
    assert "PRIVATE TEST CONTENT" not in error
    assert error.count("Report unsigned:") == 1
    assert "signature" not in value


def test_legacy_report_never_signed(signing_key):
    value = report()
    value["schema_version"] = 2
    with pytest.raises(ValueError, match="schema version 3"):
        sign_report(value, b"not schema 3")
    assert "signature" not in value


def test_cli_sign_requires_json():
    proc = subprocess.run(
        [sys.executable, "-m", "mcp_authscan.cli_wrapper", "unused", "--sign",
         "--contact", "test@example.invalid"],
        capture_output=True, text=True, timeout=15,
    )
    assert proc.returncode == 2
    assert "--sign requires --json" in proc.stderr


def test_cli_sign_uses_hash_bytes_without_scanning_network(tmp_path, signing_key, capsys):
    target = tmp_path / "owned-repo"
    target.mkdir()
    (target / "server.py").write_text("# Harmless owned source fixture\n")
    output = tmp_path / "report.json"
    argv = [sys.executable, "-m", "mcp_authscan.cli_wrapper",
            str(target), "--json", "--sign", "--output", str(output),
            "--contact", "test@example.invalid", "--authorized-by", "Fixture owner",
            "--auth-basis", "Owned local test directory", "--scope", "Local fixture only"]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    assert proc.returncode in (0, 1, 5), proc.stderr
    value = json.loads(output.read_text())
    digest, _, content = rv.compute(value, value["findings"], include_bytes=True)
    assert value["report_hash"] == digest
    signing_key.public_key().verify(
        base64.urlsafe_b64decode(value["signature"]["value"] + "=="), content,
    )
    # The site's existing verifier independently reconstructs the same bytes.
    checked = subprocess.run(
        [sys.executable, "-m", "mcp_authscan.verify_upload"],
        input=output.read_text(), capture_output=True, text=True, timeout=15,
    )
    assert checked.returncode == 0, checked.stderr
    result = json.loads(checked.stdout)
    assert result["verdict"] == "INTACT"
    assert base64.b64decode(result["canonical_bytes"]) == content
    public = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    authenticity = subprocess.run(
        ["node", "--import", "tsx", "--input-type=module", "-e",
         "import fs from 'node:fs';"
         "import {verifyAuthenticity} from './server/reportAuthenticity.ts';"
         "const v=JSON.parse(fs.readFileSync(0,'utf8'));"
         "console.log(JSON.stringify(verifyAuthenticity(true,v.signature,"
         "Buffer.from(v.bytes,'base64'),[v.key])));"],
        input=json.dumps({
            "signature": value["signature"], "bytes": result["canonical_bytes"],
            "key": {"alg": "ed25519", "key_id": value["key_id"],
                    "public_key": base64.urlsafe_b64encode(public).rstrip(b"=").decode("ascii")},
        }), capture_output=True, text=True, timeout=15,
    )
    assert authenticity.returncode == 0, authenticity.stderr
    assert json.loads(authenticity.stdout)["verdict"] == "SIGNED BY"
    # Signing must not alter the checksum or scanner's exit contract.
    unsigned = subprocess.run(
        [arg for arg in argv if arg != "--sign"],
        capture_output=True, text=True, timeout=30,
    )
    assert unsigned.returncode == proc.returncode, unsigned.stderr
    unsigned_report = json.loads(output.read_text())
    assert "signature" not in unsigned_report
    assert unsigned_report["report_hash"] == digest
