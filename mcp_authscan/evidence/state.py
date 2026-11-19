"""Evidence states: canonical serialization and state IDs.

Two independent state objects live here:

- security-state-v1 (schemas/security-state-v1.md): the authorization
  boundary. validate_state / compute_state_id.
- surface state, state_version "1": what an MCP server exposes (tool,
  prompt and resource identifiers plus digests). build_state / load_state /
  surface_state_id. Its canonical form and digests come from
  mcp_authscan.surface, which is stdlib-only and performs no I/O.

No network I/O, no file I/O.
"""
import hashlib
import json
from urllib.parse import urlsplit

from mcp_authscan import surface as _surface

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


# ---- surface state, state_version "1" ----------------------------------------
#
# {
#   "state_version": "1",
#   "surface_digest": surface.surface_digest(surface),
#   "tools":     sorted tool names,
#   "prompts":   sorted prompt names,
#   "resources": sorted resource uris,
#   "instructions_digest": sha256 of the UTF-8 instructions string ("" if absent),
#   "state_id":  sha256 of surface.compact(<this object without state_id>)
# }
#
# No timestamps, no target, no coverage: two captures of the same surface
# produce the same state_id wherever and whenever they ran.

SURFACE_STATE_VERSION = "1"
SURFACE_STATE_KEYS = (
    "state_version", "surface_digest", "tools", "prompts", "resources",
    "instructions_digest", "state_id",
)
_SURFACE_LISTS = (("tools", "name"), ("prompts", "name"), ("resources", "uri"))
_DIGEST_KEYS = ("surface_digest", "instructions_digest", "state_id")


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identifiers(items, field):
    """Sorted identifiers of the dict items carrying a string ``field``.

    Items that are not objects, or lack the field, contribute nothing here;
    they are still covered by surface_digest. Duplicates are kept.
    """
    return sorted(
        item[field] for item in items or []
        if isinstance(item, dict) and isinstance(item.get(field), str)
    )


def surface_state_id(state: dict) -> str:
    """sha256 of surface.compact(state) with any state_id key removed."""
    body = {k: v for k, v in state.items() if k != "state_id"}
    return _sha256_hex(_surface.compact(body))


def build_state(surface: dict) -> dict:
    """Build the surface state for a captured surface (capture_surface()['surface'])."""
    surface = surface or {}
    state = {
        "state_version": SURFACE_STATE_VERSION,
        "surface_digest": _surface.surface_digest(surface),
    }
    for key, field in _SURFACE_LISTS:
        state[key] = _identifiers(surface.get(key), field)
    state["instructions_digest"] = _sha256_hex(surface.get("instructions") or "")
    state["state_id"] = surface_state_id(state)
    return state


def load_state(obj) -> dict:
    """Validate a surface state and return it.

    Raises ValueError naming the offending key for: unknown or missing keys,
    a wrong state_version, a non-list or unsorted list, a malformed digest,
    or a state_id that does not match the content.
    """
    if not isinstance(obj, dict):
        raise ValueError("surface state must be a JSON object")
    for key in sorted(obj):
        if key not in SURFACE_STATE_KEYS:
            raise ValueError(f"unknown key: {key}")
    for key in SURFACE_STATE_KEYS:
        if key not in obj:
            raise ValueError(f"missing key: {key}")
    if obj["state_version"] != SURFACE_STATE_VERSION:
        raise ValueError(f"state_version: expected {SURFACE_STATE_VERSION!r}, got {obj['state_version']!r}")
    for key, _field in _SURFACE_LISTS:
        value = obj[key]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{key}: must be a list of strings")
        if value != sorted(value):
            raise ValueError(f"{key}: list is not sorted")
    for key in _DIGEST_KEYS:
        value = obj[key]
        if not (isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)):
            raise ValueError(f"{key}: must be 64 lowercase hex characters")
    expected = surface_state_id(obj)
    if obj["state_id"] != expected:
        raise ValueError(f"state_id: does not match content (expected {expected})")
    return obj
