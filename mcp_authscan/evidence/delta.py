"""boundary-delta-v1: deterministic transition between two observations.

Specification: schemas/boundary-delta-v1.md

compute_delta takes two observation-v1 envelopes, not bare states. The
observation carries the target, so a cross-target pair is refused
structurally (ValueError) instead of relying on callers to keep ledgers
straight; the state itself stays a pure boundary with no target in it.

Pure module: no I/O.
"""
from .observation import verify_observation
from .state import LIST_KEYS, compute_state_id

SCHEMA = "boundary-delta-v1"

NO_CHANGE = "NO_CHANGE"
ACCESS_CLASS_CHANGED = "ACCESS_CLASS_CHANGED"
AUTHORIZATION_REGRESSION = "AUTHORIZATION_REGRESSION"
SURFACE_EXPANDED = "SURFACE_EXPANDED"
SURFACE_REDUCED = "SURFACE_REDUCED"
DEFINITIONS_CHANGED = "DEFINITIONS_CHANGED"


def _set_diff(before, after):
    b, a = set(before), set(after)
    return {"added": sorted(a - b), "removed": sorted(b - a)}


def compute_delta(prev_obs: dict, curr_obs: dict) -> dict:
    """Return the boundary-delta-v1 object for prev_obs -> curr_obs.

    Raises ValueError if either observation is invalid, if the targets
    differ, or if curr_obs was observed before prev_obs.
    """
    verify_observation(prev_obs)
    verify_observation(curr_obs)
    if prev_obs["target"] != curr_obs["target"]:
        raise ValueError(
            f"target: refusing to compare different targets "
            f"({prev_obs['target']!r} -> {curr_obs['target']!r})")
    # Swapping prev and curr turns a regression into a reduction, so the
    # direction is checked, not assumed. RFC 3339 Z strings of equal format
    # sort in time order.
    if curr_obs["observed_at"]["start"] < prev_obs["observed_at"]["start"]:
        raise ValueError("observed_at: curr was observed before prev")
    return _classify(curr_obs["target"], prev_obs["state"], curr_obs["state"])


def delta_from_ledger(lines: list, curr_obs: dict, keys) -> dict:
    """Delta from a ledger's head row to ``curr_obs``.

    The head row must carry an attestation that verifies against ``keys``
    (published-key list): an unsigned row, an unknown key or a bad signature
    is refused, so a boundary nothing attests to can never satisfy a delta.
    Also refuses a different target or access class, an empty ledger, and a
    curr observed before the head row.
    """
    from .ledger import SIGNED, attestation_status, row_state, verify_ledger
    verify_ledger(lines, keys)
    verify_observation(curr_obs)
    header = lines[0]
    if len(lines) < 2:
        raise ValueError("ledger: no rows to compare against")
    head = lines[-1]
    status = attestation_status(header, head, keys)
    if status != SIGNED:
        raise ValueError(f"attestation: ledger head is {status}; only a signed row can satisfy a delta")
    if curr_obs["target"] != header["target"]:
        raise ValueError(
            f"target: refusing to compare different targets ({header['target']!r} -> {curr_obs['target']!r})")
    if curr_obs["state"]["access_class"] != header["access_class"]:
        raise ValueError(
            f"access_class: ledger is {header['access_class']!r}, observation is "
            f"{curr_obs['state']['access_class']!r}")
    if curr_obs["observed_at"]["start"] < head["record"]["observed_at"]["start"]:
        raise ValueError("observed_at: curr was observed before the ledger head")
    return _classify(header["target"], row_state(head), curr_obs["state"])


def _classify(target, prev, curr):
    from_id = compute_state_id(prev)
    to_id = compute_state_id(curr)
    access = {"from": prev["access_class"], "to": curr["access_class"]}
    base = {
        "schema": SCHEMA,
        "target": target,
        "access_class": access,
        "from_state_id": from_id,
        "to_state_id": to_id,
    }

    if access["from"] != access["to"]:
        return dict(base, tools=None, prompts=None, resources=None,
                    surface_digest_changed=None, instructions_changed=None,
                    classification=ACCESS_CLASS_CHANGED, rule="BD-R1")

    diffs = {key: _set_diff(prev[key], curr[key]) for key in LIST_KEYS}
    added = any(d["added"] for d in diffs.values())
    removed = any(d["removed"] for d in diffs.values())

    if from_id == to_id:
        classification, rule = NO_CHANGE, "BD-R0"
    elif access["to"] == "anonymous" and diffs["tools"]["added"]:
        classification, rule = AUTHORIZATION_REGRESSION, "BD-R2"
    elif added:
        classification, rule = SURFACE_EXPANDED, "BD-R3"
    elif removed:
        classification, rule = SURFACE_REDUCED, "BD-R4"
    else:
        classification, rule = DEFINITIONS_CHANGED, "BD-R5"

    return dict(
        base,
        tools=diffs["tools"],
        prompts=diffs["prompts"],
        resources=diffs["resources"],
        surface_digest_changed=prev["surface_digest"] != curr["surface_digest"],
        instructions_changed=prev["instructions_digest"] != curr["instructions_digest"],
        classification=classification,
        rule=rule,
    )
