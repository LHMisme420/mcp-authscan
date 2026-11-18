"""boundary-delta-v1: deterministic transition between two security states.

Specification: schemas/boundary-delta-v1.md

Pure module: standard library only, no I/O, no scanner imports.
"""
from .state import compute_state_id, validate_state

SCHEMA = "boundary-delta-v1"

NO_CHANGE = "NO_CHANGE"
AUTHORIZATION_REGRESSION = "AUTHORIZATION_REGRESSION"
EXPOSURE_COMPENSATED = "EXPOSURE_COMPENSATED"
BOUNDARY_LOOSENED = "BOUNDARY_LOOSENED"
INDETERMINATE = "INDETERMINATE"
BOUNDARY_TIGHTENED = "BOUNDARY_TIGHTENED"
CHANGED_NEUTRAL = "CHANGED_NEUTRAL"

# Field directions.
UNCHANGED = "unchanged"
TIGHTENED = "tightened"
LOOSENED = "loosened"
MIXED = "mixed"
UNDETERMINED = "undetermined"

# Compensating dimensions and how each field is compared.
#   "bool_true_tighter"  : false -> true tightens, true -> false loosens
#   "bool_false_tighter" : true -> false tightens, false -> true loosens
#   "allowlist"          : proper subset tightens, proper superset loosens,
#                          neither (entries both added and removed) is mixed
DIMENSIONS = {
    "audience": {
        "enforced": "bool_true_tighter",
        "accepted_audiences": "allowlist",
    },
    "origin": {
        "validated": "bool_true_tighter",
        "allowed_origins": "allowlist",
    },
    "cors": {
        "allow_origin_wildcard": "bool_false_tighter",
        "allow_credentials": "bool_false_tighter",
        "allowed_origins": "allowlist",
    },
}

TOOL_LISTS = ("unauthenticated_tools", "authenticated_tools")


def _field_direction(kind, before, after):
    if before == after:
        return UNCHANGED
    if before is None or after is None:
        return UNDETERMINED
    if kind == "bool_true_tighter":
        return TIGHTENED if after else LOOSENED
    if kind == "bool_false_tighter":
        return LOOSENED if after else TIGHTENED
    b, a = set(before), set(after)
    if a < b:
        return TIGHTENED
    if a > b:
        return LOOSENED
    return MIXED


def _set_diff(before, after):
    if before is None or after is None:
        if before == after:
            return {"comparable": False, "added": [], "removed": []}
        return {"comparable": False, "added": None, "removed": None}
    b, a = set(before), set(after)
    return {
        "comparable": True,
        "added": sorted(a - b),
        "removed": sorted(b - a),
    }


def _dimension(name, prev, curr):
    changes = []
    for field in sorted(DIMENSIONS[name]):
        kind = DIMENSIONS[name][field]
        before = prev[name][field]
        after = curr[name][field]
        direction = _field_direction(kind, before, after)
        if direction != UNCHANGED:
            changes.append({
                "field": field,
                "before": before,
                "after": after,
                "direction": direction,
            })
    directions = {c["direction"] for c in changes}
    loosened = bool(directions & {LOOSENED, MIXED})
    tightened = TIGHTENED in directions and not loosened
    return {
        "tightened": tightened,
        "loosened": loosened,
        "undetermined": UNDETERMINED in directions,
        "changes": changes,
    }


def compute_delta(prev: dict, curr: dict) -> dict:
    """Return the boundary-delta-v1 object describing prev -> curr.

    Raises ValueError if either state is invalid or the targets differ.
    """
    validate_state(prev)
    validate_state(curr)
    if prev["target"] != curr["target"]:
        raise ValueError("cannot compute a delta across different targets")

    from_id = compute_state_id(prev)
    to_id = compute_state_id(curr)

    tools = {
        name: _set_diff(prev["tool_visibility"][name], curr["tool_visibility"][name])
        for name in TOOL_LISTS
    }
    dims = {name: _dimension(name, prev, curr) for name in sorted(DIMENSIONS)}

    unauth = tools["unauthenticated_tools"]
    any_tightened = any(d["tightened"] for d in dims.values())
    any_loosened = any(d["loosened"] for d in dims.values())
    any_undetermined = any(d["undetermined"] for d in dims.values())

    if from_id == to_id:
        classification, rule = NO_CHANGE, "BD-R0"
    elif unauth["comparable"] and unauth["added"]:
        if any_tightened:
            classification, rule = EXPOSURE_COMPENSATED, "BD-R2"
        else:
            classification, rule = AUTHORIZATION_REGRESSION, "BD-R1"
    elif any_loosened:
        classification, rule = BOUNDARY_LOOSENED, "BD-R3"
    elif not unauth["comparable"] and unauth["added"] is None:
        classification, rule = INDETERMINATE, "BD-R4"
    elif any_undetermined:
        classification, rule = INDETERMINATE, "BD-R4"
    elif any_tightened or (unauth["comparable"] and unauth["removed"]):
        classification, rule = BOUNDARY_TIGHTENED, "BD-R5"
    else:
        classification, rule = CHANGED_NEUTRAL, "BD-R6"

    return {
        "schema": SCHEMA,
        "target": curr["target"],
        "from_state_id": from_id,
        "to_state_id": to_id,
        "tool_visibility": tools,
        "dimensions": dims,
        "compensating_tightening": [n for n in sorted(dims) if dims[n]["tightened"]],
        "classification": classification,
        "rule": rule,
    }
