"""Adversarial regression harness for the policy gate, run in CI.

Every case tampers with a report and pins the verdict policy_check.evaluate must
return. Outsider cases use the published tollbooth report and its public key
only: they model an attacker without the signing key. Insider cases re-sign
with a throwaway key generated here and trusted by the test policy: they check
that hash, scope, operations and manifest-pin rules hold even under a valid
signature. Nothing here reimplements hashing, signing or sufficiency logic.
"""
import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import policy_check, report_signing, report_verify as rv

HERE = Path(__file__).resolve().parent
PUB = HERE / "fixtures" / "published"
BASELINE = json.loads((PUB / "tollbooth-baseline.json").read_text())
PUB_KEYS = PUB / "tollbooth-baseline.keys.json"
DEFAULT_POLICY = Path(rv.__file__).resolve().parent / "policy-default.json"
ALL_OPS = ["initialize", "tools/list", "prompts/list", "resources/list"]


def _default_policy():
    return json.loads(DEFAULT_POLICY.read_text())


def _required():
    return set(_default_policy()["required-probes"])


def _evaluate(tmp_path, report, policy_path, keys_path):
    rp = tmp_path / "report.json"
    rp.write_text(json.dumps(report))
    return policy_check.evaluate(str(rp), str(policy_path), str(keys_path))


def _rehash(r):
    r["report_hash"] = rv.compute(r, r.get("findings") or [])[0]
    return r


def _all_pass(r, except_name=None):
    for p in r.get("probes") or []:
        if p.get("name") in _required():
            p["status"] = "NOT_OBSERVED" if p.get("name") == except_name else "PASS"
    return r


def _add_finding(r, rule, severity):
    finding = {k: "adversarial-fixture" for k in rv.FINDING_KEYS}
    finding["rule"], finding["severity"] = rule, severity
    r.setdefault("findings", []).append(finding)
    r["findings_count"] = len(r["findings"])
    if isinstance(r.get("severity_counts"), dict) and severity in r["severity_counts"]:
        r["severity_counts"][severity] += 1
    return r


def _ops(r, ops, established=True):
    r["content_observed"] = {"version": (BASELINE.get("content_observed") or {}).get("version"),
                             "session_established": established, "operations": list(ops),
                             "inspected": {}, "reasons": []}
    return r


# ---------------------------------------------------------------- outsider

def _o_coverage_rehashed(r):
    r["coverage"] = 1.0
    return _rehash(r)


def _o_probe_deleted(r):
    r["probes"] = [p for p in r["probes"] if p.get("name") != "issuer-identity"]
    return r


def _o_probe_edited(r):
    next(p for p in r["probes"] if p.get("name") == "token-cors")["status"] = "PASS"
    return r


def _o_ops_injected(r):
    return _ops(r, ALL_OPS)


def _o_foreign_key(r):
    other = Ed25519PrivateKey.generate()
    assert report_signing.sign_report(r, rv.signed_content(r, r.get("findings") or []), key=other)
    return r


OUTSIDER = [
    ("genuine-published-report", lambda r: r, ("CONDITIONAL", "COVERAGE")),
    ("coverage-raised-hash-recomputed", _o_coverage_rehashed, ("REJECT", "SIGNATURE-INVALID")),
    ("evidence-removed", lambda r: (r.pop("evidence"), r)[1], ("REJECT", "SIGNATURE-INVALID")),
    ("required-probe-deleted", _o_probe_deleted, ("REJECT", "SIGNATURE-INVALID")),
    ("probe-status-edited", _o_probe_edited, ("REJECT", "SIGNATURE-INVALID")),
    ("operations-injected-into-v3", _o_ops_injected, ("REJECT", "SIGNATURE-INVALID")),
    ("sig-version-relabelled-1", lambda r: (r.__setitem__("sig_version", 1), r)[1], ("REJECT", "SIGNATURE-INVALID")),
    ("re-signed-by-untrusted-key", _o_foreign_key, ("REJECT", "UNTRUSTED-SIGNER")),
]


@pytest.mark.parametrize("name,tamper,want", OUTSIDER, ids=[c[0] for c in OUTSIDER])
def test_outsider_without_the_key(tmp_path, name, tamper, want):
    out = _evaluate(tmp_path, tamper(copy.deepcopy(BASELINE)), DEFAULT_POLICY, PUB_KEYS)
    assert (out["verdict"], out["check"]) == want, out


# ---------------------------------------------------------------- insider

@pytest.fixture
def insider(tmp_path):
    """A throwaway signing key the test policy trusts; returns sign() and the policy/keys paths."""
    import base64
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = report_signing.sign_statement(key, b"insider")["key_id"]
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps([{"key_id": kid, "alg": "ed25519",
                                 "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}]))
    policy = _default_policy()
    policy["trusted-signers"] = [{"key-id": kid}]
    pp = tmp_path / "policy.json"
    pp.write_text(json.dumps(policy))

    def sign(r, version=None):
        if version is not None:
            r["sig_version"] = version
        assert report_signing.sign_report(r, rv.signed_content(r, r.get("findings") or []), key=key)
        return r
    return sign, pp, keys


def _i_hash_stale(r, sign):
    r["coverage"] = 1.0
    return sign(r)


def _i_probe_deleted(r, sign):
    r["probes"] = [p for p in r["probes"] if p.get("name") != "issuer-identity"]
    return sign(_rehash(r))


def _i_forbidden(r, sign):
    rule = _default_policy()["forbidden-findings"][0]
    return sign(_rehash(_add_finding(r, rule, "LOW")))


def _i_high(r, sign):
    return sign(_rehash(_add_finding(r, "ADVERSARIAL-1", "HIGH")))


def _i_severity_lowered(r, sign):
    _rehash(_add_finding(r, "ADVERSARIAL-1", "MEDIUM"))
    r["findings"][-1]["severity"] = "LOW"
    r["severity_counts"]["MEDIUM"] -= 1
    r["severity_counts"]["LOW"] += 1
    return sign(r)


def _i_downgrade(r, sign):
    r.pop("evidence", None)
    r.pop("provenance", None)
    return sign(r, 1)


def _i_v3_scope(r, sign):
    _all_pass(r)
    r["content_observed"] = {"version": "x", "inspected": {"tools": 1, "prompts": 1, "resources": 1}, "reasons": []}
    return sign(r, 3)


def _i_v4_met(r, sign):
    return sign(_ops(_all_pass(r), ALL_OPS), 4)


def _i_v4_missing(r, sign):
    return sign(_ops(_all_pass(r), [o for o in ALL_OPS if o != "prompts/list"]), 4)


def _i_v4_forged(r, sign):
    sign(_ops(_all_pass(r), [o for o in ALL_OPS if o != "prompts/list"]), 4)
    r["content_observed"]["operations"].append("prompts/list")
    return r


def _i_manifest(r, sign):
    r["provenance"]["tool_manifest"] = "f" * 64
    return sign(r)


def _i_version(r, sign):
    r["provenance"]["tool_version"] = "9.9.9"
    return sign(r)


def _i_original_forgery(r, sign):
    """GHSA-jvh3-qvpr-qm8q: a signed v1 report, one probe flipped with no key."""
    _all_pass(r, except_name="token-cors")
    _i_downgrade(r, sign)
    next(p for p in r["probes"] if p.get("name") == "token-cors")["status"] = "PASS"
    return r


INSIDER = [
    ("insider-control", lambda r, s: s(r), ("CONDITIONAL", "COVERAGE"), None),
    ("hash-stale-under-valid-signature", _i_hash_stale, ("REJECT", "NOT-REPRODUCIBLE"), None),
    ("required-probe-deleted-rehashed", _i_probe_deleted, ("REJECT", "PROBES-MISSING"), None),
    ("forbidden-rule-finding", _i_forbidden, ("REJECT", "FINDING-PRESENT"), None),
    ("high-finding-unlisted-rule", _i_high, ("REJECT", "FINDING-SEVERITY"), None),
    ("severity-lowered-hash-stale", _i_severity_lowered, ("REJECT", "NOT-REPRODUCIBLE"), None),
    ("sig-version-downgraded-to-1", _i_downgrade, ("REJECT", "SIG-VERSION"), None),
    ("v3-all-pass-scope-unproven", _i_v3_scope, ("CONDITIONAL", "SCOPE"), "sig_version 4 required"),
    ("v4-every-scope-operation-signed", _i_v4_met, ("CLEAN", "ALL"), None),
    ("v4-operation-not-observed", _i_v4_missing, ("CONDITIONAL", "SCOPE"), "prompts/list"),
    ("v4-operation-added-after-signing", _i_v4_forged, ("REJECT", "SIGNATURE-INVALID"), None),
    ("manifest-not-pinned", _i_manifest, ("REJECT", "MANIFEST-PIN"), "MANIFEST NOT PINNED"),
    ("version-not-pinned", _i_version, ("REJECT", "MANIFEST-PIN"), "VERSION NOT PINNED"),
    ("GHSA-jvh3-qvpr-qm8q-v1-probe-flip", _i_original_forgery, ("REJECT", "SIG-VERSION"), None),
]


@pytest.mark.parametrize("name,build,want,detail", INSIDER, ids=[c[0] for c in INSIDER])
def test_insider_with_a_trusted_key(tmp_path, insider, name, build, want, detail):
    sign, pp, keys = insider
    out = _evaluate(tmp_path, build(copy.deepcopy(BASELINE), sign), pp, keys)
    assert (out["verdict"], out["check"]) == want, out
    if detail:
        assert detail in out["detail"], out
