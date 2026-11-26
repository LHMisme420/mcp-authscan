"""Policy-controlled freshness and deployment challenge binding."""

import re
import time

LIMITS = {
    "max-assurance-age-seconds": (1, 86400),
    "max-clock-skew-seconds": (0, 300),
    "max-assessment-duration-seconds": (1, 3600),
}

CHALLENGE = re.compile(r"[0-9a-f]{64}")

POLICY_FIELDS = set(LIMITS) | {
    "expected-deployment-challenge",
    "expected-assurance-target",
}


def decision(verdict, check, detail):
    return {
        "verdict": verdict,
        "check": check,
        "detail": detail,
    }


def valid_challenge(value):
    return (
        isinstance(value, str)
        and CHALLENGE.fullmatch(value) is not None
    )


def validate_policy(policy):
    active = POLICY_FIELDS.intersection(policy)

    if not active:
        return None

    if policy.get("verified-authentication-required") is not True:
        return decision(
            "REJECT", "FRESHNESS-POLICY-INVALID",
            "Freshness requires positive authentication assurance",
        )

    for name, (minimum, maximum) in LIMITS.items():
        if name not in policy:
            continue

        value = policy[name]

        if type(value) is not int or not minimum <= value <= maximum:
            return decision(
                "REJECT", "FRESHNESS-POLICY-INVALID",
                name + " outside supported integer range",
            )

    if "expected-deployment-challenge" in policy:
        if not valid_challenge(policy["expected-deployment-challenge"]):
            return decision(
                "REJECT", "FRESHNESS-POLICY-INVALID",
                "Invalid expected deployment challenge",
            )

        if "max-assurance-age-seconds" not in policy:
            return decision(
                "REJECT", "FRESHNESS-POLICY-INVALID",
                "Deployment challenge requires maximum evidence age",
            )

        if "expected-assurance-target" not in policy:
            return decision(
                "REJECT", "FRESHNESS-POLICY-INVALID",
                "Deployment challenge requires expected target",
            )

    if "expected-assurance-target" in policy:
        target = policy["expected-assurance-target"]

        if not isinstance(target, str) or not target.strip():
            return decision(
                "REJECT", "FRESHNESS-POLICY-INVALID",
                "Expected target must be a nonempty string",
            )

    return None


def evaluate(evidence, policy, *, now=None):
    invalid = validate_policy(policy)

    if invalid:
        return invalid

    if not POLICY_FIELDS.intersection(policy):
        return None

    expected_target = policy.get("expected-assurance-target")

    if expected_target is not None:
        if evidence.get("endpoint") != expected_target:
            return decision(
                "REJECT", "ASSURANCE-TARGET-MISMATCH",
                "Evidence does not match the policy target",
            )

    expected = policy.get("expected-deployment-challenge")

    if expected is not None:
        if evidence.get("deployment_challenge") != expected:
            return decision(
                "REJECT", "DEPLOYMENT-CHALLENGE-MISMATCH",
                "Evidence is not bound to the expected challenge",
            )

    started = evidence.get("assessment_started_at")
    completed = evidence.get("assessment_completed_at")

    if started is None or completed is None:
        return decision(
            "CONDITIONAL", "ASSURANCE-TIMESTAMPS-MISSING",
            "Signed assessment timestamps required",
        )

    if (
        type(started) is not int
        or type(completed) is not int
        or started <= 0
        or completed < started
    ):
        return decision(
            "REJECT", "ASSURANCE-TIMESTAMPS-INVALID",
            "Malformed assessment interval",
        )

    current = time.time() if now is None else now

    skew = policy.get("max-clock-skew-seconds", 0)
    max_age = policy.get("max-assurance-age-seconds", 900)
    max_duration = policy.get(
        "max-assessment-duration-seconds", 120
    )

    if completed > current + skew:
        return decision(
            "REJECT", "ASSURANCE-FUTURE-DATED",
            "Assessment completion exceeds clock tolerance",
        )

    if completed - started > max_duration:
        return decision(
            "REJECT", "ASSURANCE-DURATION-EXCEEDED",
            "Assessment interval exceeds policy",
        )

    if current - started > max_age:
        return decision(
            "REJECT", "ASSURANCE-EXPIRED",
            "Assessment evidence exceeds maximum age",
        )

    return None
