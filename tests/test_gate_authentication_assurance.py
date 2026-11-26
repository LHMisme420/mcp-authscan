"""End-to-end signed authentication assurance and strict gate tests."""

import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from mcp_authscan import report_signing, report_verify
from mcp_authscan.authentication_assurance import (
    ASSURANCE_VERSION,
    CONTEXTS,
)
from .test_gate_e2e import POLICY, bundle_v3


def _read(path):
    with open(path) as file:
        return json.load(file)


def _write(path, value):
    with open(path, "w") as file:
        json.dump(value, file)


def _evidence(target, statuses=(200, 401, 401, 200)):
    return {
        "version": ASSURANCE_VERSION,
        "endpoint": target,
        "operation": "initialize",
        "redirects": False,
        "observations": [
            {
                "context": context,
                "http_status": status,
                "protocol_valid": status == 200,
                "baseline_digest": (
                    "a" * 64 if status == 200 else None
                ),
            }
            for context, status in zip(CONTEXTS, statuses)
        ],
    }


def _files(tmp_path, scenario="verified", enabled=True):
    key = Ed25519PrivateKey.generate()

    rp, pp, kp = bundle_v3(
        tmp_path, key, [("P1", "PASS")], POLICY
    )

    report = _read(rp)
    policy = _read(pp)

    policy["verified-authentication-required"] = enabled

    if scenario != "legacy":
        report["sig_version"] = 4

        content = {
            "version": "test",
            "credential_context": "credentialed",
            "session_established": True,
            "operations": ["initialize"],
            "inspected": {},
            "reasons": [],
        }

        statuses = {
            "anonymous": (200, 200, 401, 200),
            "invalid": (200, 401, 200, 200),
            "inconclusive": (200, 500, 401, 200),
            "baseline-failed": (200, 401, 401, 401),
        }.get(scenario, (200, 401, 401, 200))

        evidence = _evidence(report["target"], statuses)

        if scenario == "other-endpoint":
            evidence["endpoint"] = "https://other.invalid/mcp"

        if scenario == "moving-baseline":
            evidence["observations"][3]["baseline_digest"] = "b" * 64

        if scenario == "redirects":
            evidence["redirects"] = True

        if scenario == "unknown-version":
            evidence["version"] = "unknown"

        if scenario == "forged-verdict":
            evidence["observations"] = []
            evidence["verdict"] = "VERIFIED"

        if scenario != "missing":
            content["authentication_assurance"] = evidence

        report["content_observed"] = content

    report["report_hash"] = report_verify.compute(
        report, report["findings"]
    )[0]

    report["signature"] = report_signing.sign_statement(
        key,
        report_verify.signed_content(
            report, report["findings"]
        ),
    )

    _write(rp, report)
    _write(pp, policy)

    return rp, pp, kp


def _run(paths):
    rp, pp, kp = paths

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_authscan.strict_gate",
            str(rp),
            str(pp),
            str(kp),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.stdout.strip(), (
        result.returncode, result.stderr
    )

    decision = json.loads(result.stdout)

    print(
        f"exit={result.returncode} "
        f"{json.dumps(decision)}"
    )

    return result.returncode, decision


@pytest.mark.parametrize(
    "scenario,expected,exit_code",
    [
        ("verified", "CLEAN", 0),
        ("anonymous", "REJECT", 1),
        ("invalid", "REJECT", 1),
        ("inconclusive", "CONDITIONAL", 2),
        ("baseline-failed", "CONDITIONAL", 2),
        ("moving-baseline", "CONDITIONAL", 2),
        ("other-endpoint", "CONDITIONAL", 2),
        ("missing", "CONDITIONAL", 2),
        ("legacy", "CONDITIONAL", 2),
        ("redirects", "CONDITIONAL", 2),
        ("unknown-version", "CONDITIONAL", 2),
        ("forged-verdict", "CONDITIONAL", 2),
    ],
)
def test_signed_assurance_gate(
    tmp_path, scenario, expected, exit_code
):
    paths = _files(tmp_path, scenario)
    code, decision = _run(paths)

    assert code == exit_code, decision
    assert decision["verdict"] == expected, decision


@pytest.mark.parametrize(
    "mutation",
    [
        "remove-evidence",
        "change-status",
        "change-protocol",
        "change-digest",
        "change-endpoint",
        "change-context",
        "change-redirects",
        "change-version",
    ],
)
def test_signed_assurance_tampering(tmp_path, mutation):
    paths = _files(tmp_path)
    rp = paths[0]

    report = _read(rp)
    content = report["content_observed"]
    evidence = content["authentication_assurance"]

    if mutation == "remove-evidence":
        del content["authentication_assurance"]

    elif mutation == "change-status":
        evidence["observations"][1]["http_status"] = 403

    elif mutation == "change-protocol":
        evidence["observations"][1]["protocol_valid"] = True

    elif mutation == "change-digest":
        evidence["observations"][0]["baseline_digest"] = "c" * 64

    elif mutation == "change-endpoint":
        evidence["endpoint"] = "https://other.invalid/mcp"

    elif mutation == "change-context":
        evidence["observations"][1]["context"] = "credentialed"

    elif mutation == "change-redirects":
        evidence["redirects"] = True

    elif mutation == "change-version":
        evidence["version"] = "tampered"

    # Intentionally retain the original signature.
    _write(rp, report)

    code, decision = _run(paths)

    assert code == 1, decision
    assert decision["verdict"] == "REJECT", decision


def test_historical_report_original_policy(tmp_path):
    paths = _files(tmp_path, "legacy", enabled=False)

    code, decision = _run(paths)

    assert code == 0, decision
    assert decision["verdict"] == "CLEAN", decision


@pytest.mark.parametrize("invalid", ["true", 1, [], {}])
def test_invalid_policy_type_rejected(tmp_path, invalid):
    paths = _files(tmp_path)
    pp = paths[1]

    policy = _read(pp)
    policy["verified-authentication-required"] = invalid
    _write(pp, policy)

    code, decision = _run(paths)

    assert code == 1, decision
    assert decision["verdict"] == "REJECT", decision


def test_secure_regressed_remediated(tmp_path):
    observed = []

    for name, scenario in (
        ("secure", "verified"),
        ("regressed", "anonymous"),
        ("remediated", "verified"),
    ):
        directory = tmp_path / name
        directory.mkdir()

        paths = _files(directory, scenario)
        code, decision = _run(paths)

        observed.append((code, decision["verdict"]))

    assert observed == [
        (0, "CLEAN"),
        (1, "REJECT"),
        (0, "CLEAN"),
    ]
