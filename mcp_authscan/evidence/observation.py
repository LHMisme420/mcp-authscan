"""observation-v1: verification.

Specification: schemas/observation-v1.md

Pure module: standard library only, no I/O, no scanner imports.
"""
import re

from .state import SECTIONS, compute_state_id

SCHEMA = "observation-v1"
_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_COUNT_KEYS = ("in_scope", "pass", "fail", "not_observed", "excluded")


def null_fields(state: dict) -> list:
    """Dotted paths of every null field in a security state, sorted."""
    return sorted(
        f"{section}.{field}"
        for section in SECTIONS
        for field, value in state[section].items()
        if value is None
    )


def verify_observation(obs: dict) -> None:
    """Raise ValueError unless obs passes observation-v1 §5."""
    if not isinstance(obs, dict) or obs.get("schema") != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA!r}")
    state = obs.get("state")
    if not isinstance(state, dict):
        raise ValueError("state must be a JSON object")
    recomputed = compute_state_id(state)  # validates the state too
    if obs.get("state_id") != recomputed:
        raise ValueError(f"state_id {obs.get('state_id')!r} != recomputed {recomputed}")
    if state.get("state_id") is not None and state["state_id"] != recomputed:
        raise ValueError("state.state_id disagrees with the envelope state_id")

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
            if not isinstance(e.get("affects"), list):
                raise ValueError(f"{key} entries need an affects list")

    if "unestablished" in obs:
        listed = sorted(e.get("field") for e in obs["unestablished"])
        if listed != null_fields(state):
            raise ValueError(f"unestablished fields {listed} != null state fields {null_fields(state)}")
