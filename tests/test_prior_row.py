"""evidence-binding-v3: the signed report carries the prior head row inline.

A reader holding only report B, the run-B observation and the published
keys can check what the surface was before run B and compute the delta,
with no ledger file and no earlier report.
"""
import base64
import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import report_verify as rv
from mcp_authscan.evidence.delta import delta_from_report
from mcp_authscan.evidence.ledger import SIGNED, verify_row
from mcp_authscan.evidence.state import normalize_target
from mcp_authscan.report_signing import sign_statement
from mcp_authscan.verify_upload import verify_text
from tests.evidence_fixtures import FixtureServer

ROOT = Path(__file__).resolve().parents[1]
AUTH = ["--allow-private", "--contact", "t@example.test", "--authorized-by", "T", "--auth-basis", "local fixture"]


@pytest.fixture(scope="module")
def two_runs(tmp_path_factory):
    """Run A, then the server exposes a new anonymous tool, then run B. Then delete
    report A and the whole ledger root: only report B and its observation remain."""
    tmp = tmp_path_factory.mktemp("prior")
    key = Ed25519PrivateKey.generate()
    (tmp / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    (tmp / "home").mkdir()
    env = dict(os.environ, HOME=str(tmp / "home"), MCP_AUTHSCAN_SIGNING_KEY=str(tmp / "k.pem"),
               PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    for var in ("MCPAUTHSCAN_TOKEN", "MCP_AUTHSCAN_LEDGER_DIR"):
        env.pop(var, None)

    def run(name):
        out = tmp / name
        out.mkdir()
        proc = subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json", "--sign",
                               "--output", str(out / "report.json"), "--evidence-dir", str(out / "ev"), *AUTH],
                              capture_output=True, text=True, timeout=120, env=env, cwd=out)
        assert proc.returncode == 1, proc.stderr
        return out

    with FixtureServer(anonymous_tools=["list_docs"]) as (url, cfg):
        a = run("a")
        cfg["anonymous_tools"] = ["delete_doc", "list_docs"]
        b = run("b")
    report_a = json.loads((a / "report.json").read_text())
    shutil.rmtree(a)
    shutil.rmtree(tmp / "home" / ".config" / "mcp-authscan" / "ledgers")
    report_b = json.loads((b / "report.json").read_text())
    obs_b = json.loads(next((b / "ev").glob("observation-*.json")).read_text())
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = [{"key_id": sign_statement(key, b"x")["key_id"], "alg": "ed25519",
             "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")}]
    return report_a, report_b, obs_b, keys, key.public_key()


def _entry(report):
    [entry] = report["evidence"]["states"]
    return entry


def test_first_run_has_no_prior_row(two_runs):
    report_a = two_runs[0]
    entry = _entry(report_a)
    assert report_a["evidence"]["scheme"] == "evidence-binding-v3"
    assert (entry["ledger_head"], entry["prior_row"]) == (None, None)


def test_report_b_carries_run_a_row_signed(two_runs):
    report_a, report_b, _, keys, _ = two_runs
    row = _entry(report_b)["prior_row"]
    assert row["state_id"] == _entry(report_b)["ledger_head"] == _entry(report_a)["state_id"]
    assert row["record"]["report_hash"] == report_a["report_hash"]
    assert row["tools"] == ["list_docs"]                          # the prior surface, from the report alone
    header = {"schema": "boundary-ledger-v1", "target": normalize_target(report_b["target"]), "access_class": "anonymous"}
    assert verify_row(header, row, keys) == SIGNED


def test_delta_from_report_alone(two_runs):
    _, report_b, obs_b, keys, _ = two_runs                         # ledger and report A are gone
    d = delta_from_report(report_b, "anonymous", obs_b, keys)
    assert (d["classification"], d["tools"]["added"]) == ("AUTHORIZATION_REGRESSION", ["delete_doc"])
    assert d["from_state_id"] == _entry(report_b)["ledger_head"]
    assert d["to_state_id"] == _entry(report_b)["state_id"]


def _report_signature_valid(report, public):
    try:
        content = rv.signed_content(report, report["findings"])
    except ValueError:
        return False
    try:
        public.verify(base64.urlsafe_b64decode(report["signature"]["value"] + "=="), content)
        return True
    except InvalidSignature:
        return False


def test_report_signature_covers_the_prior_row(two_runs):
    _, report_b, _, keys, public = two_runs
    assert _report_signature_valid(report_b, public)
    assert verify_text(json.dumps(report_b))["verdict"] == "INTACT"
    tampered = copy.deepcopy(report_b)
    tampered["evidence"]["states"][0]["prior_row"]["tools"] = []
    assert not _report_signature_valid(tampered, public)
    assert rv.compute(tampered, tampered["findings"])[0] == report_b["report_hash"]   # hash unaffected


def test_swapped_prior_row_is_refused(two_runs):
    _, report_b, obs_b, keys, _ = two_runs
    forged = copy.deepcopy(report_b)
    forged["evidence"]["states"][0]["prior_row"]["record"]["report_hash"] = "f" * 64
    with pytest.raises(ValueError, match="SIGNATURE INVALID"):
        delta_from_report(forged, "anonymous", obs_b, keys)
    mismatched = copy.deepcopy(report_b)
    mismatched["evidence"]["states"][0]["ledger_head"] = "a" * 64
    with pytest.raises(ValueError, match="prior_row.state_id must equal ledger_head"):
        rv.evidence_binding(mismatched)


def test_unknown_key_cannot_satisfy_delta_from_report(two_runs):
    _, report_b, obs_b, _, _ = two_runs
    other = Ed25519PrivateKey.generate()
    raw = other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = [{"key_id": sign_statement(other, b"x")["key_id"], "alg": "ed25519",
             "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")}]
    with pytest.raises(ValueError, match="UNKNOWN KEY"):
        delta_from_report(report_b, "anonymous", obs_b, keys)


SITE_VERIFY_JS = ("import fs from 'node:fs';"
                  "import {verifyAuthenticity} from './server/reportAuthenticity.ts';"
                  "const v=JSON.parse(fs.readFileSync(0,'utf8'));"
                  "const bytes=typeof v.bytes==='string'?Buffer.from(v.bytes,'base64'):null;"
                  "console.log(JSON.stringify(verifyAuthenticity(true,v.signature,bytes,[v.key])));")


def test_site_verifier_signed_by_on_report_with_prior_row(two_runs):
    _, report_b, _, keys, _ = two_runs
    assert _entry(report_b)["prior_row"] is not None
    result = verify_text(json.dumps(report_b))
    proc = subprocess.run(["node", "--import", "tsx", "--input-type=module", "-e", SITE_VERIFY_JS],
                          input=json.dumps({"signature": report_b["signature"], "bytes": result["canonical_bytes"],
                                            "key": keys[0]}), capture_output=True, text=True, timeout=15, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    assert (result["verdict"], json.loads(proc.stdout)["verdict"]) == ("INTACT", "SIGNED BY")
