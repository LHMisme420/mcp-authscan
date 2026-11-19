"""boundary-ledger-v1: append-only chain of states for one target at one access class.

Specification: schemas/boundary-ledger-v1.md

Line 1 is a header naming the target and access class; every later line is
a security-state-v1 object carrying state_id and previous_state_id. Appends
go through an observation-v1, which carries the target, so an observation
of a different target or class is refused structurally (ValueError).

verify_ledger / append_entry are pure. read_ledger / append_observation are
the only file I/O in the evidence package.
"""
import json
import os

from .observation import verify_observation
from .state import ACCESS_CLASSES, compute_state_id, normalize_target, validate_state

SCHEMA = "boundary-ledger-v1"


def make_header(target: str, access_class: str) -> dict:
    if normalize_target(target) != target:
        raise ValueError(f"target: must be normalized, got {target!r}")
    if access_class not in ACCESS_CLASSES:
        raise ValueError(f"access_class: must be one of {', '.join(ACCESS_CLASSES)}")
    return {"schema": SCHEMA, "target": target, "access_class": access_class}


def verify_ledger(lines: list) -> str | None:
    """Verify parsed ledger lines (header first). Return the head STATE ID
    (None for a header-only ledger). Raises ValueError naming the line."""
    if not lines:
        raise ValueError("line 1: missing header")
    header = lines[0]
    if not isinstance(header, dict) or sorted(header) != ["access_class", "schema", "target"]:
        raise ValueError("line 1: header must be {schema, target, access_class}")
    if header["schema"] != SCHEMA:
        raise ValueError(f"line 1: schema must be {SCHEMA!r}")
    try:
        make_header(header["target"], header["access_class"])
    except ValueError as e:
        raise ValueError(f"line 1: {e}") from None
    prev_id = None
    for n, entry in enumerate(lines[1:], start=2):
        try:
            validate_state(entry)
        except ValueError as e:
            raise ValueError(f"line {n}: {e}") from None
        if "state_id" not in entry or "previous_state_id" not in entry:
            raise ValueError(f"line {n}: entries must carry state_id and previous_state_id")
        if entry["state_id"] != compute_state_id(entry):
            raise ValueError(f"line {n}: state_id does not match content")
        if entry["previous_state_id"] != prev_id:
            raise ValueError(f"line {n}: previous_state_id breaks the chain")
        if entry["state_id"] == prev_id:
            raise ValueError(f"line {n}: no-op append (same state as line {n - 1})")
        if entry["access_class"] != header["access_class"]:
            raise ValueError(f"line {n}: access_class differs from the ledger's")
        prev_id = entry["state_id"]
    return prev_id


def append_entry(lines: list, observation: dict) -> dict | None:
    """Return the entry to append for ``observation``, or None if it matches the head.

    Raises ValueError if the observation is invalid or names a different
    target or access class than the ledger header.
    """
    head = verify_ledger(lines)
    verify_observation(observation)
    header = lines[0]
    if observation["target"] != header["target"]:
        raise ValueError(f"target: ledger is for {header['target']!r}, observation is for {observation['target']!r}")
    state = observation["state"]
    if state["access_class"] != header["access_class"]:
        raise ValueError(f"access_class: ledger is {header['access_class']!r}, "
                         f"observation is {state['access_class']!r}")
    state_id = compute_state_id(state)
    if state_id == head:
        return None
    entry = {k: v for k, v in state.items() if k not in ("state_id", "previous_state_id")}
    entry["state_id"] = state_id
    entry["previous_state_id"] = head
    return entry


def read_ledger(path) -> list:
    """Parse and verify a ledger file; return its lines (header first)."""
    with open(path, encoding="utf-8") as fh:
        lines = [json.loads(line) for line in fh.read().splitlines()]
    verify_ledger(lines)
    return lines


def append_observation(path, observation: dict) -> dict | None:
    """Append ``observation``'s state to the ledger at ``path``.

    Creates the ledger (header from the observation) if the file does not
    exist. Returns the appended entry, or None when the state equals the head.
    """
    if os.path.exists(path):
        lines = read_ledger(path)
    else:
        lines = [make_header(observation["target"], observation["state"]["access_class"])]
    entry = append_entry(lines, observation)
    if entry is None and len(lines) > 1:
        return None
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    mode = "a" if os.path.exists(path) else "w"
    with open(path, mode, encoding="utf-8") as fh:
        if mode == "w":
            fh.write(json.dumps(lines[0], sort_keys=True, separators=(",", ":")) + "\n")
        if entry is not None:
            fh.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    return entry
