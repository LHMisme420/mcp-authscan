"""security-state-v1: canonical serialization and STATE ID.

Specification: schemas/security-state-v1.md

Pure module: standard library only, no I/O, no scanner imports.
"""
import hashlib
import json
from urllib.parse import urlsplit

SCHEMA = "security-state-v1"

# Top-level keys that are never part of the STATE ID preimage.
ID_EXCLUDED_KEYS = ("state_id", "previous_state_id")

# Required structure. Each section maps field name -> kind.
#   "list"          : sorted, duplicate-free list of strings (never null)
#   "list|null"     : as "list", or null (not determined)
#   "bool|null"     : true, false, or null (not determined)
SECTIONS = {
    "tool_visibility": {
        "unauthenticated_tools": "list|null",
        "authenticated_tools": "list|null",
    },
    "audience": {
        "enforced": "bool|null",
        "accepted_audiences": "list|null",
    },
    "origin": {
        "validated": "bool|null",
        "allowed_origins": "list|null",
    },
    "cors": {
        "allow_origin_wildcard": "bool|null",
        "allow_credentials": "bool|null",
        "allowed_origins": "list|null",
    },
}

TOP_LEVEL_KEYS = frozenset(("schema", "target") + tuple(SECTIONS)) | frozenset(ID_EXCLUDED_KEYS)


def canonical_json(obj) -> str:
    """Serialize obj as canonical JSON.

    Sorted keys at every level, no insignificant whitespace, ASCII-only
    output (non-ASCII escaped as \\uXXXX), NaN/Infinity rejected.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_target(url: str) -> str:
    """Normalize a target URL per security-state-v1 §3.

    Lowercase scheme and host, drop the scheme's default port, keep the path
    as given, drop query, fragment and userinfo.
    """
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS or not parts.hostname:
        raise ValueError(f"target must be an absolute http(s) URL: {url!r}")
    host = parts.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    netloc = host if port is None or port == _DEFAULT_PORTS[scheme] else f"{host}:{port}"
    return f"{scheme}://{netloc}{parts.path}"


def _check_list(path, value):
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    for item in value:
        if not isinstance(item, str):
            raise ValueError(f"{path} items must be strings")
    # Python str ordering is Unicode code point ordering, as the spec requires.
    if value != sorted(value):
        raise ValueError(f"{path} must be sorted by Unicode code point")
    if len(set(value)) != len(value):
        raise ValueError(f"{path} must not contain duplicates")


def validate_state(state: dict) -> None:
    """Raise ValueError if state does not conform to security-state-v1."""
    if not isinstance(state, dict):
        raise ValueError("state must be a JSON object")
    unknown = set(state) - TOP_LEVEL_KEYS
    if unknown:
        raise ValueError("unknown top-level keys: {}".format(", ".join(sorted(unknown))))
    if state.get("schema") != SCHEMA:
        raise ValueError(f"schema must be {SCHEMA!r}")
    target = state.get("target")
    if not isinstance(target, str) or not target:
        raise ValueError("target must be a non-empty string")
    for section, fields in SECTIONS.items():
        if section not in state:
            raise ValueError(f"missing required section: {section}")
        body = state[section]
        if not isinstance(body, dict):
            raise ValueError(f"{section} must be an object")
        extra = set(body) - set(fields)
        if extra:
            raise ValueError("unknown keys in {}: {}".format(section, ", ".join(sorted(extra))))
        for field, kind in fields.items():
            path = f"{section}.{field}"
            if field not in body:
                raise ValueError(f"missing required field: {path}")
            value = body[field]
            if value is None and kind.endswith("|null"):
                continue
            if kind.startswith("list"):
                _check_list(path, value)
            elif kind.startswith("bool"):
                if not isinstance(value, bool):
                    raise ValueError(f"{path} must be a boolean or null")
    for key in ID_EXCLUDED_KEYS:
        if key in state and state[key] is not None and not _is_state_id(state[key]):
            raise ValueError(f"{key} must be a 64-char lowercase hex SHA-256 or null")


def _is_state_id(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def id_preimage(state: dict) -> str:
    """Return the canonical JSON string that is hashed to form the STATE ID."""
    validate_state(state)
    body = {k: v for k, v in state.items() if k not in ID_EXCLUDED_KEYS}
    return canonical_json(body)


def compute_state_id(state: dict) -> str:
    """STATE ID: lowercase hex SHA-256 of the canonical JSON of the state,
    with any top-level state_id / previous_state_id keys removed."""
    return hashlib.sha256(id_preimage(state).encode("ascii")).hexdigest()
