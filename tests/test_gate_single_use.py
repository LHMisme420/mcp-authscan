"""End-to-end signed deployment authorization and replay tests."""

import hashlib
import json
import sqlite3
import subprocess
import sys
import time
import threading

from concurrent.futures import ThreadPoolExecutor

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from mcp_authscan import (
    challenge_registry,
    report_signing,
    report_verify,
)

from .test_gate_e2e import POLICY, bundle_v3
from .test_gate_authentication_assurance import _evidence


DEPLOYMENT = "authscan-deployment-001"


def prepare(tmp_path, scenario="valid"):
    key = Ed25519PrivateKey.generate()

    rp, pp, kp = bundle_v3(
        tmp_path, key, [("P1", "PASS")], POLICY
    )

    with open(rp) as f:
        report = json.load(f)

    with open(pp) as f:
        policy = json.load(f)

    target = report["target"]
    db = str(tmp_path / "challenges.sqlite3")

    record = challenge_registry.issue(
        db, target, DEPLOYMENT
    )

    policy.update({
        "min-sig-version": 4,
        "verified-authentication-required": True,
        "single-use-authorization-required": True,
        "expected-deployment-challenge": record["challenge"],
        "expected-assurance-target": target,
        "max-assurance-age-seconds": 900,
        "max-clock-skew-seconds": 0,
        "max-assessment-duration-seconds": 120,
    })

    evidence = _evidence(target)

    evidence.update({
        "deployment_challenge": record["challenge"],
        "assessment_started_at": record["issued_at"],
        "assessment_completed_at": int(time.time()),
    })

    if scenario == "contradicted":
        evidence = _evidence(target, (200, 200, 401, 200))
        evidence.update({
            "deployment_challenge": record["challenge"],
            "assessment_started_at": record["issued_at"],
            "assessment_completed_at": int(time.time()),
        })

    elif scenario == "inconclusive":
        evidence["observations"] = []

    elif scenario == "wrong-challenge":
        evidence["deployment_challenge"] = "f" * 64

    elif scenario == "wrong-target":
        policy["expected-assurance-target"] = (
            "https://other.invalid/mcp"
        )

    elif scenario == "preissued":
        evidence["assessment_started_at"] = (
            record["issued_at"] - 1
        )

    elif scenario == "stale":
        evidence["assessment_started_at"] = (
            record["issued_at"] - 1000
        )
        evidence["assessment_completed_at"] = (
            record["issued_at"] - 999
        )

    elif scenario == "policy-disabled":
        policy["single-use-authorization-required"] = False

    report["sig_version"] = 4

    report["content_observed"] = {
        "version": "single-use-test",
        "credential_context": "credentialed",
        "session_established": True,
        "operations": ["initialize"],
        "inspected": {},
        "reasons": [],
        "authentication_assurance": evidence,
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

    if scenario == "tampered":
        evidence["assessment_started_at"] -= 1

    with open(rp, "w") as f:
        json.dump(report, f)

    with open(pp, "w") as f:
        json.dump(policy, f)

    return rp, pp, kp, db, record


def run(paths, deployment=DEPLOYMENT, registry=True):
    rp, pp, kp, db, record = paths

    command = [
        sys.executable,
        "-m",
        "mcp_authscan.strict_gate",
        rp, pp, kp,
    ]

    if registry:
        command.extend([
            "--challenge-db", db,
            "--deployment-id", deployment,
        ])

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.stdout.strip(), result.stderr

    return result.returncode, json.loads(result.stdout)


def consumed(paths):
    db = paths[3]
    challenge = paths[4]["challenge"]

    with sqlite3.connect(db) as connection:
        row = connection.execute(
            """
            SELECT consumed_at, report_digest
            FROM deployment_challenges
            WHERE challenge = ?
            """,
            (challenge,),
        ).fetchone()

    return row


def test_signed_single_use(tmp_path):
    paths = prepare(tmp_path)

    code, decision = run(paths)

    assert code == 0
    assert decision["verdict"] == "CLEAN"
    assert decision["check"] == "SINGLE-USE-AUTHORIZED"

    code, decision = run(paths)

    assert code == 1
    assert decision["check"] == "CHALLENGE-NOT-AUTHORIZED"


def test_exact_report_bytes_recorded(tmp_path):
    paths = prepare(tmp_path)

    with open(paths[0], "rb") as f:
        expected = hashlib.sha256(f.read()).hexdigest()

    code, decision = run(paths)

    assert code == 0
    assert decision["report_sha256"] == expected
    assert consumed(paths)[1] == expected


@pytest.mark.parametrize("scenario,expected", [
    ("contradicted", 1),
    ("inconclusive", 2),
    ("wrong-challenge", 1),
    ("wrong-target", 1),
    ("preissued", 1),
    ("stale", 1),
    ("tampered", 1),
    ("policy-disabled", 1),
])
def test_rejected_reports_do_not_consume(
    tmp_path, scenario, expected
):
    paths = prepare(tmp_path, scenario)

    code, decision = run(paths)

    assert code == expected, decision
    assert consumed(paths) == (None, None)


def test_wrong_deployment_does_not_consume(tmp_path):
    paths = prepare(tmp_path)

    assert run(paths, deployment="different")[0] == 1
    assert consumed(paths) == (None, None)

    assert run(paths)[0] == 0


def test_registry_cannot_be_omitted(tmp_path):
    paths = prepare(tmp_path)

    code, decision = run(paths, registry=False)

    assert code == 1
    assert decision["check"] == "SINGLE-USE-CONFIGURATION"
    assert consumed(paths) == (None, None)


def test_unavailable_registry_fails_closed(tmp_path):
    paths = prepare(tmp_path)

    broken = (
        paths[0], paths[1], paths[2],
        str(tmp_path / "missing" / "registry.db"),
        paths[4],
    )

    code, decision = run(broken)

    assert code == 1
    assert decision["check"] == "CHALLENGE-REGISTRY-ERROR"
    assert consumed(paths) == (None, None)


def test_concurrent_signed_report_replay(tmp_path):
    paths = prepare(tmp_path)

    workers = 16
    barrier = threading.Barrier(workers)

    def attempt(_):
        barrier.wait(timeout=30)
        return run(paths)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    authorized = [
        decision for code, decision in results
        if code == 0
    ]

    rejected = [
        decision for code, decision in results
        if code == 1
    ]

    print(
        f"\n[SIGNED REPLAY] Attempts={workers} "
        f"Authorized={len(authorized)} "
        f"Rejected={len(rejected)}"
    )

    assert len(authorized) == 1
    assert len(rejected) == 15

    assert all(
        d["check"] == "CHALLENGE-NOT-AUTHORIZED"
        for d in rejected
    )

    assert consumed(paths)[0] is not None
