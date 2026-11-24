"""Regression tests for gate hardening (branch gate-hardening).

1. min-sig-version below the floor is REJECT, and the default policy sets 3
2. forbidden-findings match exact rule IDs or separator-delimited families only
3. acceptable-verdicts is not read: required probes must PASS (654e85b)
4. policy-level fail-on rejects findings at or above it, and unknown severities
"""
import sys
sys.path.insert(0, "/home/lhmisme/mcp-authscan/tests")
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import report_verify
from test_gate_e2e import POLICY
from test_gate_mutations import gate, gate_v3

DEFAULT_POLICY = Path(__file__).resolve().parents[1] / "mcp_authscan" / "policy-default.json"


def with_policy(**extra):
    p = dict(POLICY)
    p.update(extra)
    return p


def add_finding(rule, severity):
    def mutate(payload):
        finding = {k: "gatecheck" for k in report_verify.FINDING_KEYS}
        finding["rule"] = rule
        finding["severity"] = severity
        payload.setdefault("findings", []).append(finding)
        if "findings_count" in payload:
            payload["findings_count"] = len(payload["findings"])
        counts = payload.get("severity_counts")
        if isinstance(counts, dict) and severity in counts:
            counts[severity] += 1
    return mutate


# 1. signature-version floor

def test_default_policy_sets_hardened_values():
    p = json.loads(DEFAULT_POLICY.read_text())
    assert p["min-sig-version"] == 3
    assert p["fail-on"] == "high"
    assert p["acceptable-verdicts"] == ["PASS"]


def test_sig_version_below_floor_rejects(tmp_path):
    out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")], with_policy(**{"min-sig-version": 3}))
    assert (out["verdict"], out["check"]) == ("REJECT", "SIG-VERSION"), out


def test_no_floor_leaves_clean_report_clean(tmp_path):
    out = gate_v3(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")])
    assert out["verdict"] == "CLEAN", out


# 2. denylist matching

@pytest.mark.parametrize("rule,forbidden,rejected", [
    ("CORS-1", "CORS-1", True),
    (" cors-1 ", "CORS-1", True),
    ("CORS-1-variant", "CORS-1", True),
    ("CORS-10", "CORS-1", False),
    ("ZERO-AUTHX", "ZERO-AUTH", False),
])
def test_forbidden_rule_matching(tmp_path, rule, forbidden, rejected):
    out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")],
               with_policy(**{"forbidden-findings": [forbidden]}), mutate=add_finding(rule, "LOW"))
    assert (out["check"] == "FINDING-PRESENT") is rejected, out


# 3. acceptable-verdicts cannot loosen sufficiency

def test_acceptable_verdicts_cannot_admit_not_observed(tmp_path):
    out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "NOT_OBSERVED")],
               with_policy(**{"acceptable-verdicts": ["NOT_OBSERVED", "EXCLUDED"]}))
    assert out["verdict"] != "CLEAN", out


# 4. severity floor

@pytest.mark.parametrize("severity,rejected", [
    ("CRITICAL", True),
    ("HIGH", True),
    ("MEDIUM", False),
    ("LOW", False),
])
def test_fail_on_severity(tmp_path, severity, rejected):
    out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")],
               with_policy(**{"fail-on": "high"}), mutate=add_finding("X-1", severity))
    assert (out["check"] == "FINDING-SEVERITY") is rejected, out


def test_fail_on_unknown_severity_rejects_or_cannot_be_hashed(tmp_path):
    try:
        out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")],
                   with_policy(**{"fail-on": "high"}), mutate=add_finding("X-1", "BOGUS"))
    except ValueError:
        return  # report_verify refuses to hash it, so it can never reach the gate
    assert (out["verdict"], out["check"]) == ("REJECT", "FINDING-SEVERITY"), out


def test_invalid_fail_on_value_rejects(tmp_path):
    out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")], with_policy(**{"fail-on": "severe"}))
    assert (out["verdict"], out["check"]) == ("REJECT", "POLICY-INVALID"), out


# 5. scope: CLEAN needs the declared scope proven by signed content

SCOPE = {"operations": ["initialize", "tools/list"]}


def test_declared_scope_without_signed_proof_is_not_clean(tmp_path):
    out = gate_v3(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")], with_policy(scope=SCOPE))
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SCOPE"), out


def test_claimed_content_observation_does_not_prove_scope(tmp_path):
    def claim(payload):
        payload["content_observed"] = {"version": "t", "inspected": {"tools": 3, "prompts": 1, "resources": 1}, "reasons": []}
    out = gate(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")], with_policy(scope=SCOPE), mutate=claim)
    assert out["verdict"] != "CLEAN", out


def test_no_declared_scope_still_reaches_clean(tmp_path):
    out = gate_v3(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")])
    assert out["verdict"] == "CLEAN", out


def test_high_finding_without_fail_on_is_conditional(tmp_path):
    """Addition: no fail-on declared + a HIGH finding -> CONDITIONAL naming the top
    severity, never CLEAN (and the CLI exit stays 0 since the verdict is not REJECT)."""
    out = gate_v3(tmp_path, Ed25519PrivateKey.generate(), [("P1", "PASS")], mutate=add_finding("X-1", "HIGH"))
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SEVERITY"), out
    assert "HIGH" in out["detail"], out
