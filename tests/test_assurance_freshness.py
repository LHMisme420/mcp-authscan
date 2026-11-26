"""Freshness, challenge binding and signed evidence regression tests."""

import json
import time

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from mcp_authscan import (
    assurance_freshness as f,
    report_signing,
    report_verify,
)

from .test_gate_e2e import POLICY, bundle_v3
from .test_gate_authentication_assurance import _evidence, _run


NOW = 1800000000
CHALLENGE = "a" * 64
TARGET = "https://example.invalid/mcp"

POL = {
    "verified-authentication-required": True,
    "max-assurance-age-seconds": 900,
    "max-clock-skew-seconds": 60,
    "max-assessment-duration-seconds": 120,
    "expected-deployment-challenge": CHALLENGE,
    "expected-assurance-target": TARGET,
}


def evidence():
    return {
        "endpoint": TARGET,
        "assessment_started_at": NOW - 10,
        "assessment_completed_at": NOW,
        "deployment_challenge": CHALLENGE,
    }


def test_fresh_evidence():
    assert f.evaluate(evidence(), POL, now=NOW) is None


@pytest.mark.parametrize("field,value,expected", [
    ("assessment_started_at", NOW - 901, "REJECT"),
    ("assessment_completed_at", NOW + 61, "REJECT"),
    ("assessment_started_at", NOW + 1, "REJECT"),
    ("assessment_started_at", True, "REJECT"),
    ("assessment_completed_at", "invalid", "REJECT"),
    ("assessment_completed_at", None, "CONDITIONAL"),
    ("assessment_started_at", None, "CONDITIONAL"),
    ("assessment_started_at", -1, "REJECT"),
    ("assessment_started_at", NOW - 121, "REJECT"),
    ("deployment_challenge", "b" * 64, "REJECT"),
    ("deployment_challenge", None, "REJECT"),
    ("endpoint", "https://other.invalid/mcp", "REJECT"),
])
def test_adversarial_evidence(field, value, expected):
    data = evidence()
    data[field] = value

    result = f.evaluate(data, POL, now=NOW)

    assert result["verdict"] == expected


@pytest.mark.parametrize("field,value", [
    ("max-assurance-age-seconds", True),
    ("max-assurance-age-seconds", 0),
    ("max-assurance-age-seconds", -1),
    ("max-assurance-age-seconds", "900"),
    ("max-assurance-age-seconds", 86401),
    ("max-clock-skew-seconds", 301),
    ("max-clock-skew-seconds", -1),
    ("max-assessment-duration-seconds", 0),
    ("expected-deployment-challenge", "short"),
    ("expected-deployment-challenge", "A" * 64),
    ("expected-assurance-target", ""),
    ("verified-authentication-required", False),
])
def test_invalid_policy(field, value):
    policy = {**POL, field: value}

    assert f.validate_policy(policy)["verdict"] == "REJECT"


def test_historical_policy_unchanged():
    assert f.evaluate({}, {}, now=NOW) is None


def test_age_boundary():
    data = evidence()
    data["assessment_started_at"] = NOW - 900
    data["assessment_completed_at"] = NOW - 899

    assert f.evaluate(data, POL, now=NOW) is None

    assert f.evaluate(
        data, POL, now=NOW + 1
    )["check"] == "ASSURANCE-EXPIRED"


def test_challenge_requires_target():
    policy = dict(POL)
    del policy["expected-assurance-target"]

    assert f.validate_policy(policy)["verdict"] == "REJECT"


def test_challenge_requires_expiration():
    policy = dict(POL)
    del policy["max-assurance-age-seconds"]

    assert f.validate_policy(policy)["verdict"] == "REJECT"


@pytest.mark.parametrize("scenario,expected", [
    ("fresh", 0),
    ("expired", 1),
    ("future", 1),
    ("wrong-challenge", 1),
    ("wrong-target", 1),
    ("missing-timestamps", 2),
    ("tampered-timestamp", 1),
    ("tampered-challenge", 1),
    ("tampered-completion", 1),
])
def test_signed_freshness_gate(tmp_path, scenario, expected):

    key = Ed25519PrivateKey.generate()

    paths = bundle_v3(
        tmp_path,
        key,
        [("P1", "PASS")],
        POLICY,
    )

    rp, pp, kp = paths

    with open(rp) as file:
        report = json.load(file)

    with open(pp) as file:
        policy = json.load(file)

    now = int(time.time())

    policy.update(POL)
    policy["expected-assurance-target"] = report["target"]

    data = _evidence(report["target"])

    data.update({
        "assessment_started_at": now - 10,
        "assessment_completed_at": now,
        "deployment_challenge": CHALLENGE,
    })

    if scenario == "expired":
        data["assessment_started_at"] = now - 1000
        data["assessment_completed_at"] = now - 990

    elif scenario == "future":
        data["assessment_started_at"] = now + 600
        data["assessment_completed_at"] = now + 610

    elif scenario == "wrong-challenge":
        data["deployment_challenge"] = "b" * 64

    elif scenario == "wrong-target":
        policy["expected-assurance-target"] = TARGET + "/other"

    elif scenario == "missing-timestamps":
        del data["assessment_started_at"]
        del data["assessment_completed_at"]

    report["sig_version"] = 4

    report["content_observed"] = {
        "version": "test",
        "credential_context": "credentialed",
        "session_established": True,
        "operations": ["initialize"],
        "inspected": {},
        "reasons": [],
        "authentication_assurance": data,
    }

    report["report_hash"] = report_verify.compute(
        report, report["findings"]
    )[0]

    report["signature"] = report_signing.sign_statement(
        key,
        report_verify.signed_content(
            report, report["findings"]
        ),
    )

    if scenario == "tampered-timestamp":
        data["assessment_started_at"] -= 1

    elif scenario == "tampered-challenge":
        data["deployment_challenge"] = "c" * 64

    elif scenario == "tampered-completion":
        data["assessment_completed_at"] += 1

    with open(rp, "w") as file:
        json.dump(report, file)

    with open(pp, "w") as file:
        json.dump(policy, file)

    code, decision = _run(paths)

    assert code == expected, decision
