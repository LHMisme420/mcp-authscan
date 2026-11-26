"""Offline, fail-closed assurance status for independently verified report artifacts.

Policy observation times are operator attestations pinned to raw file SHA-256, not
signed timestamps from the current report format. CURRENT means policy conditions
were met at evaluation time, NOT proof of continuing endpoint security.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

from . import verification

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERDICTS = {"CURRENT", "STALE", "REGRESSED", "INCONCLUSIVE"}


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _stamp(text):
    if not isinstance(text, str) or not text.endswith("Z"):
        raise ValueError("observation timestamp must be UTC ISO-8601 ending in Z")
    value = datetime.fromisoformat(text[:-1] + "+00:00")
    if value.utcoffset().total_seconds() != 0:
        raise ValueError("observation timestamp must be UTC")
    return value


def _policy(policy):
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    age = policy.get("max_age_days")
    if type(age) not in (int, float) or not 0 < age <= 3650:
        raise ValueError("max_age_days must be a positive number <= 3650")
    if not isinstance(policy.get("target"), str) or not policy["target"].strip():
        raise ValueError("target is required")
    classes = policy.get("required_probe_classes")
    if not isinstance(classes, dict) or not classes or any(
        not isinstance(k, str) or not k or not isinstance(v, list) or not v
        or any(not isinstance(n, str) or not n for n in v)
        for k, v in classes.items()
    ):
        raise ValueError("required_probe_classes must map class names to signed probe-name lists")
    if type(policy.get("require_second_run", False)) is not bool:
        raise ValueError("require_second_run must be boolean")
    obs = policy.get("observations")
    if not isinstance(obs, list) or not obs:
        raise ValueError("observations must contain at least one SHA-256/time record")
    seen = set()
    for o in obs:
        if not isinstance(o, dict) or set(o) != {"file_sha256", "observed_at"}:
            raise ValueError("each observation requires only file_sha256 and observed_at")
        digest = o["file_sha256"]
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest) or digest in seen:
            raise ValueError("observation hashes must be unique SHA-256 hex")
        seen.add(digest)
        _stamp(o["observed_at"])


def _check_report(data: bytes, anchor):
    try:
        document = json.loads(data)
        result = verification.verify(data, anchor=anchor)
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return None, "report is unreadable"
    if not isinstance(document, dict):
        return None, "report must be a JSON object"
    if result.get("integrity", {}).get("verdict") != "INTACT":
        return None, "report integrity not verified"
    if result.get("authenticity", {}).get("verdict") != "SIGNED BY":
        return None, "report signature not verified"
    if result.get("probe_statuses", {}).get("verdict") != "VERIFIED":
        return None, "signed probe statuses not verified"
    if document.get("hash_scheme") != "verdict-v4":
        return None, "verdict-v4 required for graded probe comparisons"
    if not isinstance(document.get("report_hash"), str) or not _HEX64.fullmatch(document["report_hash"]):
        return None, "graded hash missing"
    return document, None


def evaluate(policy, reports: list[bytes], *, now=None, anchor="packaged"):
    """Returns a single verdict object. All reports verified before comparing their claims.

    ``anchor`` is "packaged" (the pinned key history) or a dict from
    verification.external_anchor(); None is refused so signatures are never skipped.
    """
    policy_hash = hashlib.sha256(_canonical(policy)).hexdigest()
    out = {"schema": "authscan-assurance-verdict-v1", "verdict": "INCONCLUSIVE",
           "reason": "", "policy_sha256": policy_hash, "policy_target": policy.get("target") if isinstance(policy, dict) else None,
           "prior_report_hash": None, "latest_report_hash": None}

    def finish(status, reason):
        assert status in _VERDICTS
        out.update(verdict=status, reason=reason)
        return out

    try:
        _policy(policy)
    except (ValueError, TypeError) as e:
        return finish("INCONCLUSIVE", "invalid policy: " + str(e))

    if anchor != "packaged" and not (isinstance(anchor, dict) and anchor.get("keys")):
        return finish("INCONCLUSIVE", "trust anchor unavailable")
    if not reports:
        return finish("INCONCLUSIVE", "no report provided")
    pins = {o["file_sha256"]: _stamp(o["observed_at"]) for o in policy["observations"]}
    accepted = []
    for raw in reports:
        file_sha = hashlib.sha256(raw).hexdigest()
        doc, problem = _check_report(raw, anchor)
        if problem:
            return finish("INCONCLUSIVE", problem)
        if file_sha not in pins:
            return finish("INCONCLUSIVE", "report bytes have no policy-pinned observation time")
        if doc.get("target") != policy["target"]:
            return finish("INCONCLUSIVE", "report target differs from policy target")
        probes = doc.get("probes")
        if not isinstance(probes, list):
            return finish("INCONCLUSIVE", "signed probe rows unavailable")
        signed_names = {p.get("name") for p in probes if isinstance(p, dict)
                        and p.get("status") in {"PASS", "FAIL"}}
        for class_name, names in policy["required_probe_classes"].items():
            if not any(n in signed_names for n in names):
                return finish("INCONCLUSIVE", f"required class {class_name} has no conclusive signed probe")
        accepted.append((pins[file_sha], file_sha, doc))
    accepted.sort(key=lambda r: r[0])
    if len({row[1] for row in accepted}) != len(accepted):
        return finish("INCONCLUSIVE", "duplicate report supplied")
    prior = accepted[0][2]
    latest = accepted[-1][2]
    out["prior_report_hash"] = prior["report_hash"]
    out["latest_report_hash"] = latest["report_hash"]

    if len(accepted) >= 2:
        if len({r[0] for r in accepted}) != len(accepted):
            return finish("INCONCLUSIVE", "reports have ambiguous observation ordering")
        if any(r[2]["report_hash"] != prior["report_hash"] for r in accepted[1:]):
            return finish("REGRESSED", "newer signed report on same target has different graded content; security impact not inferred")

    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    latest_time = accepted[-1][0]
    if latest_time > current:
        return finish("INCONCLUSIVE", "policy observation time is in the future")
    elapsed = (current - latest_time).total_seconds() / 86400
    if elapsed > policy["max_age_days"]:
        return finish("STALE", f"latest policy-anchored observation is {elapsed:.2f} days old (limit {policy['max_age_days']})")
    if policy.get("require_second_run", False) and len(accepted) < 2:
        return finish("INCONCLUSIVE", "policy requires second signed run; only one report supplied")
    return finish("CURRENT", "signed graded evidence matches policy at its pinned observation time; age alone proves no continuing security")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="mcp-authscan assurance")
    parser.add_argument("--report", action="append", required=True, help="signed JSON; repeat for a newer run")
    parser.add_argument("--policy", required=True, help="JSON policy with pinned observation times")
    parser.add_argument("--artifact", help="write machine-readable verdict JSON to this path")
    parser.add_argument("--trust-anchor", metavar="FILE",
                        help="key-history-v1 or keys.json file to verify signatures against "
                             "(default: the packaged pinned key history)")
    args = parser.parse_args(argv)

    def unavailable(reason):
        return {"schema": "authscan-assurance-verdict-v1", "verdict": "INCONCLUSIVE",
                "reason": reason, "prior_report_hash": None,
                "policy_sha256": None, "latest_report_hash": None}

    try:
        anchor = "packaged" if args.trust_anchor is None else verification.external_anchor(args.trust_anchor)
    except verification.AnchorError as exc:
        anchor, result = None, unavailable("trust anchor invalid: " + str(exc))
    if anchor is not None:
        try:
            policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))
            raw = [Path(path).read_bytes() for path in args.report]
            result = evaluate(policy, raw, anchor=anchor)
        except (OSError, ValueError, TypeError):
            result = unavailable("input unavailable or invalid")
    if args.artifact:
        Path(args.artifact).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["verdict"] + " " + result["reason"].replace("\n", " "))
    return 0 if result["verdict"] == "CURRENT" else 1


if __name__ == "__main__":
    sys.exit(main())
