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
from mcp_authscan import verification
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
    try:
        content = rv.signed_content(report, report["findings"])
    except ValueError:
        return False        # the declared form cannot be reconstructed: unverifiable
    try:
        public.verify(base64.urlsafe_b64decode(report["signature"]["value"] + "=="), content)
        return True
    except InvalidSignature:
        return False


def test_signed_report_binds_state_id(signed_scan):
    report, public = signed_scan
    # The content probe records operations, so a signed scan is sig_version 4.
    assert report["sig_version"] == 4 and isinstance(report["content_observed"]["operations"], list)
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


def _graded():
    return {"schema_version": 3, "hash_scheme": "verdict-v3", "target": "https://x.example/mcp",
            "status": "completed", "total_checks": 1, "findings_count": 0, "probe_set_version": "t",
            "coverage": 1.0, "severity_counts": rv.severity_counts([])}


EV = {"scheme": "evidence-binding-v1", "states": [{"access_class": "anonymous", "state_id": "a" * 64}]}


def test_old_reports_without_sig_version_are_form_1():
    payload = _graded()
    assert "sig_version" not in payload
    assert rv.signed_content(payload, []) == rv.compute(payload, [], include_bytes=True)[2]
    assert rv.signed_content(dict(payload, sig_version=1), []) == rv.signed_content(payload, [])


def test_form_2_bytes_carry_sig_version():
    content = rv.signed_content(dict(_graded(), sig_version=2, evidence=EV), [])
    assert json.loads(content) == {"sig_version": 2, "evidence": EV, "report": rv.canonical_report(_graded(), [])}


@pytest.mark.parametrize("extra, match", [
    ({"evidence": EV}, "sig_version: 1 does not cover"),                 # evidence with no declared form
    ({"sig_version": 1, "evidence": EV}, "sig_version: 1 does not cover"),
    ({"sig_version": 2}, "requires an evidence field"),
    ({"sig_version": 5, "evidence": EV}, "unknown value"),
    ({"sig_version": "2", "evidence": EV}, "unknown value"),
    ({"sig_version": True, "evidence": EV}, "unknown value"),
])
def test_form_is_declared_not_inferred(extra, match):
    with pytest.raises(ValueError, match=match):
        rv.signed_content(dict(_graded(), **extra), [])


def test_downgrading_sig_version_breaks_signature_not_hash(signed_scan):
    report, public = signed_scan
    for change in ({"sig_version": 1}, {"sig_version": None}):
        tampered = copy.deepcopy(report)
        if change["sig_version"] is None:
            del tampered["sig_version"]
        else:
            tampered.update(change)
        assert not _signature_valid(tampered, public)
        assert rv.compute(tampered, tampered["findings"])[0] == report["report_hash"]


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


# ---- the site verifier on a report that carries evidence ----------------------

def _site_verdict(report, public):
    """The site's verdict for this report, as server/reportVerification.ts gets it.

    The route runs mcp_authscan.verify_upload, which prints mcp_authscan.verification's
    result with the packaged trust anchor; Node only reshapes it. This fixture's key is
    not published, so the engine is asked here with that key as the trust anchor, and the
    real adapter subprocess must agree on every stage except the anchor-dependent one.
    """
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    anchor = verification.anchor_from_keys([{"alg": "ed25519", "key_id": report["key_id"],
                                             "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")}])
    result = verification.verify(json.dumps(report), anchor=anchor)
    checked = subprocess.run([sys.executable, "-m", "mcp_authscan.verify_upload"], input=json.dumps(report),
                             capture_output=True, text=True, timeout=15, cwd=ROOT)
    assert checked.returncode == 0, checked.stderr
    route = json.loads(checked.stdout)
    assert route["trust_anchor"]["source"] == "packaged"
    for stage in ("catalog", "format", "integrity"):
        assert route[stage] == result[stage]
    # Verdicts reached after key lookup depend on the anchor; this fixture key is not published.
    if result["authenticity"]["verdict"] in ("SIGNED BY", "SIGNATURE INVALID", "DIVERGENCE", "KEY NOT VALID"):
        assert route["authenticity"]["verdict"] == "UNKNOWN KEY"
    else:
        assert route["authenticity"]["verdict"] == result["authenticity"]["verdict"]
    return result["integrity"]["verdict"], result["authenticity"]["verdict"]


def test_site_verifier_signed_by_on_evidence_report(signed_scan):
    report, public = signed_scan
    assert report["sig_version"] == 4 and report["evidence"]["states"]
    assert _site_verdict(report, public) == ("INTACT", "SIGNED BY")


def test_site_verifier_rejects_edited_state_id(signed_scan):
    report, public = signed_scan
    edited = copy.deepcopy(report)
    sid = edited["evidence"]["states"][0]["state_id"]
    edited["evidence"]["states"][0]["state_id"] = ("0" if sid[0] != "0" else "1") + sid[1:]
    assert _site_verdict(edited, public) == ("INTACT", "SIGNATURE INVALID")


@pytest.mark.parametrize("strip", ["evidence", "sig_version"])
def test_site_verifier_refuses_stripped_form(signed_scan, strip):
    report, public = signed_scan
    stripped = copy.deepcopy(report)
    del stripped[strip]
    # report_hash still matches; the declared signed form can no longer be built, so the
    # engine reports DIVERGENCE (signed content cannot be rebuilt), never SIGNED BY.
    integrity, authenticity = _site_verdict(stripped, public)
    assert (integrity, authenticity) == ("INTACT", "DIVERGENCE")
