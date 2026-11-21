"""Offline structural checks for inline reference evidence-binding-v3 rows.

No ledger access or attestation trust is implied: the reference uses an empty
key list here, checking row structure and state identity only.
"""
import hashlib
import json
from urllib.parse import urlsplit

CONTENT_KEYS = (
    "state_version", "access_class", "surface_digest",
    "tools", "prompts", "resources", "instructions_digest",
)


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def validate_prior_row(payload, entry):
    row = entry["prior_row"]
    parts = urlsplit(payload.get("target", ""))
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("evidence.states target must be an absolute http(s) URL")
    # Access the port as the reference's normalize_target does (reject invalid ports).
    _ = parts.port
    state = {k: v for k, v in row.items() if k != "record"}
    if (set(state) - set(CONTENT_KEYS) - {"state_id", "previous_state_id"}
            or any(k not in state for k in CONTENT_KEYS)
            or state["state_version"] != "1"
            or state["access_class"] not in ("anonymous", "authenticated")):
        raise ValueError("evidence.states prior_row has malformed state fields")
    for key in ("tools", "prompts", "resources"):
        value = state[key]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value) or value != sorted(value):
            raise ValueError(f"evidence.states prior_row {key} must be sorted strings")
    for key in ("surface_digest", "instructions_digest"):
        if not _hex64(state[key]):
            raise ValueError(f"evidence.states prior_row {key} must be 64 lowercase hex")
    for key in ("state_id", "previous_state_id"):
        if key not in state or (state[key] is not None and not _hex64(state[key])):
            raise ValueError(f"evidence.states prior_row {key} is malformed")
    expected = hashlib.sha256(json.dumps(
        {k: state[k] for k in CONTENT_KEYS}, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")).hexdigest()
    if state["state_id"] is not None and state["state_id"] != expected:
        raise ValueError("evidence.states prior_row state_id does not match content")
    if state["access_class"] != entry["access_class"]:
        raise ValueError("evidence.states prior_row access_class differs")
    record = row.get("record")
    if not isinstance(record, dict) or sorted(record) != ["attestation", "observed_at", "report_hash"]:
        raise ValueError("evidence.states prior_row record is malformed")
    if not _hex64(record["report_hash"]):
        raise ValueError("evidence.states prior_row report_hash is malformed")
    observed = record["observed_at"]
    if (not isinstance(observed, dict) or sorted(observed) != ["end", "start"]
            or not all(isinstance(v, str) for v in observed.values())):
        raise ValueError("evidence.states prior_row observed_at is malformed")
    att = record["attestation"]
    if att is not None and (not isinstance(att, dict) or sorted(att) != ["alg", "key_id", "value"]
                           or att["alg"] != "ed25519" or not _hex64(att["key_id"])
                           or not isinstance(att["value"], str)):
        raise ValueError("evidence.states prior_row attestation is malformed")
