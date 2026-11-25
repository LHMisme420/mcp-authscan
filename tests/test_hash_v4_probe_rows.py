"""verdict-v4 commits to each probe row; volatile fields stay outside the hash."""
import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # gate helpers live beside this file

from mcp_authscan import report_verify as rv
from mcp_authscan import verification
from mcp_authscan.monolith import PROBE_SET_VERSION
from mcp_authscan.oauth_probes_v2 import ProbeRecord


def _report(scheme=rv.HASH_SCHEME_V4):
    probes = [
        ProbeRecord(1, "issuer-identity", "PASS", http_status=200,
                    headers_observed={"content-type": "application/json", "date": "Wed, 25 Nov 2026 15:00:00 GMT"},
                    body_excerpt='{"issuer":"https://as.example"}', body_sha256="a" * 64,
                    detail="issuer present", endpoint="https://as.example/.well-known/oauth-authorization-server").as_dict(),
        ProbeRecord(4, "token-cors", "EXCLUDED", prerequisite_met=False,
                    limitation="No client credential, so no credentialed request was sent").as_dict(),
    ]
    payload = {
        "target": "https://mcp.example/mcp", "status": "completed", "total_checks": 2,
        "findings_count": 0, "probe_set_version": PROBE_SET_VERSION, "coverage": {},
        "severity_counts": rv.severity_counts([]), "findings": [], "probes": probes,
        "hash_scheme": scheme, "schema_version": rv.SCHEMA_VERSION,
        "run_started_at": "2026-11-25T15:00:00+00:00",
    }
    payload["report_hash"] = rv.compute(payload, [])[0]
    if scheme == rv.HASH_SCHEME_V4:
        payload["evidence_hash_scheme"] = rv.EVIDENCE_HASH_SCHEME
        payload["evidence_hash"] = rv.evidence_hash(probes)
    return payload


def _integrity(payload):
    return verification.verify(json.dumps(payload), anchor=None)["integrity"]


def _verdict(payload):
    return _integrity(payload)["verdict"]


def _mutated(base, fn):
    copy_ = copy.deepcopy(base)
    fn(copy_)
    return copy_


def test_v4_report_is_intact_and_names_its_scheme():
    result = verification.verify(json.dumps(_report()), anchor=None)
    assert result["integrity"]["verdict"] == "INTACT"
    assert result["integrity"]["hash_scheme"] == "verdict-v4"
    assert result["format"]["algorithm"] == "SHA-256 / verdict-v4"


def test_graded_probe_fields_change_the_hash():
    base = _report()
    cases = {
        "status": lambda p: p["probes"][0].update(status="FAIL"),
        "limitation": lambda p: p["probes"][1].update(limitation="edited limitation text"),
    }
    for name, fn in cases.items():
        changed = _mutated(base, fn)
        assert rv.compute(changed, [])[0] != base["report_hash"], name
        assert _verdict(changed) == "ALTERED", name


def test_body_digest_moves_evidence_hash_not_graded_hash():
    base = _report()
    changed = _mutated(base, lambda p: p["probes"][0].update(body_sha256="b" * 64))
    assert rv.compute(changed, [])[0] == base["report_hash"]
    assert rv.evidence_hash(changed["probes"]) != base["evidence_hash"]
    integ = _integrity(changed)
    assert (integ["graded_verdict"], integ["evidence_verdict"], integ["verdict"]) == ("INTACT", "ALTERED", "ALTERED")


def test_v4_without_evidence_hash_is_unreadable():
    base = _report()
    del base["evidence_hash"]
    assert verification.verify(json.dumps(base), anchor=None)["failed_stage"] == "format"


def _to_v4(payload):
    for probe in payload["probes"]:
        for key in rv.PROBE_ROW_KEYS + rv.EVIDENCE_ROW_KEYS:
            probe.setdefault(key, None)
    payload["hash_scheme"] = rv.HASH_SCHEME_V4
    payload["evidence_hash_scheme"] = rv.EVIDENCE_HASH_SCHEME
    payload["evidence_hash"] = rv.evidence_hash(payload["probes"])


def test_gate_min_graded_scheme(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from test_gate_e2e import POLICY
    from test_gate_mutations import gate_v3
    for d in "abcd":
        (tmp_path / d).mkdir()
    key, ok = Ed25519PrivateKey.generate(), [("P1", "PASS"), ("P2", "PASS")]
    floor = dict(POLICY, **{"min-graded-scheme": "verdict-v4"})
    old = gate_v3(tmp_path / "a", key, ok, floor, mutate=lambda p: None)
    assert (old["verdict"], old["check"]) == ("REJECT", "GRADED-SCHEME"), old
    new = gate_v3(tmp_path / "b", key, ok, floor, mutate=_to_v4)
    assert new["verdict"] == "CLEAN", new
    assert gate_v3(tmp_path / "c", key, ok, POLICY)["verdict"] == "CLEAN"      # no floor: v3 still passes
    bad = gate_v3(tmp_path / "d", key, ok, dict(POLICY, **{"min-graded-scheme": "verdict-v9"}))
    assert bad["check"] == "POLICY-INVALID", bad


def test_volatile_fields_do_not_change_the_hash():
    base = _report()
    cases = {
        "timestamp": lambda p: p.update(run_started_at="2027-01-01T00:00:00+00:00"),
        "header": lambda p: p["probes"][0]["headers_observed"].update(date="Thu, 01 Jan 2027 00:00:00 GMT"),
    }
    for name, fn in cases.items():
        changed = _mutated(base, fn)
        assert rv.compute(changed, [])[0] == base["report_hash"], name
        assert _verdict(changed) == "INTACT", name


def test_v3_reports_still_verify_under_v3_and_ignore_probe_rows():
    v3 = _report(rv.HASH_SCHEME)
    result = verification.verify(json.dumps(v3), anchor=None)
    assert result["integrity"]["verdict"] == "INTACT"
    assert result["integrity"]["hash_scheme"] == "verdict-v3"
    v3["probes"][0]["status"] = "FAIL"                      # outside the v3 hash, as before
    assert _verdict(v3) == "INTACT"


def test_relabeling_a_v4_report_as_v3_does_not_match():
    v4 = _report()
    v4["hash_scheme"] = rv.HASH_SCHEME
    assert _verdict(v4) == "ALTERED"


def test_cli_prints_scheme(tmp_path, capsys):
    path = tmp_path / "r.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")
    rv.main([str(path)])
    out = capsys.readouterr().out
    r = _report()
    assert "verdict-v4=" + r["report_hash"] in out
    assert "probe-evidence-v1=" + r["evidence_hash"] in out
