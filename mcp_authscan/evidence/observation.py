"""observation-v1: verification.

Specification: schemas/observation-v1.md

Pure module: no I/O.
"""
import re

from .state import build_state, compute_state_id, normalize_target, validate_state

SCHEMA = "observation-v1"
_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_COUNT_KEYS = ("in_scope", "pass", "fail", "not_observed", "excluded")
CAPTURE_STATUSES = ("complete", "refused")


def verify_observation(obs: dict) -> None:
    """Raise ValueError unless obs passes observation-v1 §5."""
    if not isinstance(obs, dict) or obs.get("schema") != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA!r}")
    target = obs.get("target")
    if not isinstance(target, str) or normalize_target(target) != target:
        raise ValueError("target must be a normalized http(s) URL")
    state = obs.get("state")
    if not isinstance(state, dict):
        raise ValueError("state must be a JSON object")
    validate_state(state)
    recomputed = compute_state_id(state)
    if obs.get("state_id") != recomputed:
        raise ValueError(f"state_id {obs.get('state_id')!r} != recomputed {recomputed}")

    observed = obs.get("observed_at") or {}
    start, end = observed.get("start"), observed.get("end")
    for name, value in (("start", start), ("end", end)):
        if not isinstance(value, str) or not _RFC3339_Z.match(value):
            raise ValueError(f"observed_at.{name} must be an RFC 3339 UTC timestamp ending in Z")
    assert isinstance(start, str) and isinstance(end, str)
    if end < start:  # same fixed-width format, so string order is time order
        raise ValueError("observed_at.end is earlier than observed_at.start")

    scanner = obs.get("scanner") or {}
    for key in ("name", "version", "probe_set_version"):
        if not isinstance(scanner.get(key), str) or not scanner[key]:
            raise ValueError(f"scanner.{key} must be a non-empty string")

    cov = obs.get("coverage") or {}
    for key in _COUNT_KEYS:
        if not isinstance(cov.get(key), int) or isinstance(cov[key], bool) or cov[key] < 0:
            raise ValueError(f"coverage.{key} must be a non-negative integer")
    if cov["in_scope"] != cov["pass"] + cov["fail"] + cov["not_observed"]:
        raise ValueError("coverage.in_scope != pass + fail + not_observed")
    for key, field in (("not_observed", "reason"), ("excluded", "missing_prerequisite")):
        entries = obs.get(key)
        if not isinstance(entries, list):
            raise ValueError(f"{key} must be a list")
        if cov[key] != len(entries):
            raise ValueError(f"coverage.{key} != len({key})")
        for e in entries:
            if not isinstance(e.get("probe_id"), str) or not isinstance(e.get(field), str):
                raise ValueError(f"{key} entries need string probe_id and {field}")

    if "capture" in obs:
        capture = obs["capture"]
        if (not isinstance(capture, dict) or sorted(capture) != ["reasons", "status"]
                or capture["status"] not in CAPTURE_STATUSES
                or not isinstance(capture["reasons"], list)
                or not all(isinstance(r, str) for r in capture["reasons"])):
            raise ValueError("capture must be {status: complete|refused, reasons: [str]}")
        if capture["status"] == "refused":
            # A refusal is only ever recorded around the empty anonymous state.
            if recomputed != build_state({}, "anonymous")["state_id"]:
                raise ValueError("capture: refused is only valid for the empty anonymous state")
            if not capture["reasons"]:
                raise ValueError("capture: a refusal must record its reason")
