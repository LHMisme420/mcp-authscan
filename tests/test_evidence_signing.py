"""The STATE ID is inside the signature and outside report_hash.

report_hash must stay recomputable from graded content alone, so the
evidence binding is not hashed. The signature covers graded content plus the
binding (report_verify.signed_content), so editing or removing a bound
STATE ID breaks the signature while leaving report_hash unchanged.
"""
import base64
import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import report_verify as rv
from mcp_authscan.verify_upload import verify_text
from tests.evidence_fixtures import FixtureServer

ROOT = Path(__file__).resolve().parents[1]
AUTH = ["--allow-private", "--contact", "t@example.test", "--authorized-by", "T", "--auth-basis", "local fixture"]


@pytest.fixture(scope="module")
def signed_scan(tmp_path_factory):
    """One real signed scan of a fixture server; key supplied only via the env var."""
    tmp = tmp_path_factory.mktemp("signed")
    key = Ed25519PrivateKey.generate()
    key_file = tmp / "keys" / "k.pem"
    key_file.parent.mkdir()
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    home = tmp / "empty-home"
    home.mkdir()
    env = dict(os.environ, MCP_AUTHSCAN_SIGNING_KEY=str(key_file), HOME=str(home),
               PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    env.pop("MCPAUTHSCAN_TOKEN", None)
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json", "--sign",
                               "--output", str(tmp / "report.json"), *AUTH],
                              capture_output=True, text=True, timeout=120, env=env, cwd=tmp)
    assert proc.returncode == 1, proc.stderr
    return json.loads((tmp / "report.json").read_text()), key.public_key()


def _signature_valid(report, public):
    content = rv.signed_content(report, report["findings"])
    try:
        public.verify(base64.urlsafe_b64decode(report["signature"]["value"] + "=="), content)
        return True
    except InvalidSignature:
        return False


def test_signed_report_binds_state_id(signed_scan):
    report, public = signed_scan
    [entry] = report["evidence"]["states"]
    assert entry["access_class"] == "anonymous" and len(entry["state_id"]) == 64
    assert _signature_valid(report, public)
    # verify_upload hands the site verifier exactly the bytes that were signed.
    result = verify_text(json.dumps(report))
    assert result["verdict"] == "INTACT"
    assert base64.b64decode(result["canonical_bytes"]) == rv.signed_content(report, report["findings"])


def test_editing_state_id_breaks_signature_not_hash(signed_scan):
    report, public = signed_scan
    edited = copy.deepcopy(report)
    sid = edited["evidence"]["states"][0]["state_id"]
    edited["evidence"]["states"][0]["state_id"] = ("0" if sid[0] != "0" else "1") + sid[1:]
    assert not _signature_valid(edited, public)
    assert rv.compute(edited, edited["findings"])[0] == report["report_hash"]
    assert verify_text(json.dumps(edited))["verdict"] == "INTACT"   # integrity unaffected; authenticity is what broke


def test_removing_state_id_leaves_report_hash_unchanged_and_breaks_signature(signed_scan):
    report, public = signed_scan
    stripped = copy.deepcopy(report)
    del stripped["evidence"]
    assert rv.compute(stripped, stripped["findings"])[0] == report["report_hash"]
    assert verify_text(json.dumps(stripped))["verdict"] == "INTACT"
    assert not _signature_valid(stripped, public)


def test_report_without_evidence_signs_the_hash_preimage_unchanged():
    payload = {"schema_version": 3, "hash_scheme": "verdict-v3", "target": "https://x.example/mcp",
               "status": "completed", "total_checks": 1, "findings_count": 0, "probe_set_version": "t",
               "coverage": 1.0, "severity_counts": rv.severity_counts([])}
    assert rv.signed_content(payload, []) == rv.compute(payload, [], include_bytes=True)[2]


@pytest.mark.parametrize("evidence", [
    {"scheme": "evidence-binding-v1", "states": [{"access_class": "root", "state_id": "a" * 64}]},
    {"scheme": "evidence-binding-v1", "states": [{"access_class": "anonymous", "state_id": "XYZ"}]},
    {"scheme": "evidence-binding-v1", "states": [{"access_class": "authenticated", "state_id": "a" * 64},
                                                 {"access_class": "anonymous", "state_id": "b" * 64}]},
    {"scheme": "other", "states": []},
    {"scheme": "evidence-binding-v1", "states": [], "extra": 1},
])
def test_malformed_binding_is_refused(evidence):
    payload = {"schema_version": 3, "hash_scheme": "verdict-v3", "target": "https://x.example/mcp",
               "status": "completed", "total_checks": 1, "findings_count": 0, "probe_set_version": "t",
               "coverage": 1.0, "severity_counts": rv.severity_counts([]), "evidence": evidence}
    with pytest.raises(ValueError, match="evidence"):
        rv.signed_content(payload, [])
