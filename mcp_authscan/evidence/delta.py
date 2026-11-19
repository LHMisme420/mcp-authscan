"""boundary-delta-v1: deterministic transition between two security states.

Specification: schemas/boundary-delta-v1.md

Pure module: no I/O. A state only describes one access class, so states of
different classes are never compared: the result is ACCESS_CLASS_CHANGED.
"""
from .state import LIST_KEYS, compute_state_id, validate_state

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


def compute_delta(prev: dict, curr: dict) -> dict:
    """Return the boundary-delta-v1 object for prev -> curr.

    Raises ValueError if either state is invalid.
    """
    validate_state(prev)
    validate_state(curr)
    from_id = compute_state_id(prev)
    to_id = compute_state_id(curr)
    access = {"from": prev["access_class"], "to": curr["access_class"]}

    if access["from"] != access["to"]:
        return {
            "schema": SCHEMA,
            "access_class": access,
            "from_state_id": from_id,
            "to_state_id": to_id,
            "tools": None,
            "prompts": None,
            "resources": None,
            "surface_digest_changed": None,
            "instructions_changed": None,
            "classification": ACCESS_CLASS_CHANGED,
            "rule": "BD-R1",
        }

    diffs = {key: _set_diff(prev[key], curr[key]) for key in LIST_KEYS}
    added = any(d["added"] for d in diffs.values())
    removed = any(d["removed"] for d in diffs.values())
    surface_changed = prev["surface_digest"] != curr["surface_digest"]
    instructions_changed = prev["instructions_digest"] != curr["instructions_digest"]

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

    return {
        "schema": SCHEMA,
        "access_class": access,
        "from_state_id": from_id,
        "to_state_id": to_id,
        "tools": diffs["tools"],
        "prompts": diffs["prompts"],
        "resources": diffs["resources"],
        "surface_digest_changed": surface_changed,
        "instructions_changed": instructions_changed,
        "classification": classification,
        "rule": rule,
    }
