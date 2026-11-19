"""security-state-v1: the surface state, its canonical form and its STATE ID.

Specification: schemas/security-state-v1.md

A security state is what one MCP server exposes at one access class:

    {
      "state_version": "1",
      "access_class": "anonymous" | "authenticated",
      "surface_digest": surface.surface_digest(surface),
      "tools":     sorted tool names,
      "prompts":   sorted prompt names,
      "resources": sorted resource uris,
      "instructions_digest": sha256 of the UTF-8 instructions string
    }

plus the chaining keys ``state_id`` and ``previous_state_id``, which are never
part of the STATE ID. No timestamps, no target, no coverage.

Canonical form and surface_digest come from mcp_authscan.surface
(stdlib-only, no I/O). This module performs no network or file I/O.
"""
import hashlib
from urllib.parse import urlsplit

from mcp_authscan import surface as _surface

STATE_VERSION = "1"
ACCESS_CLASSES = ("anonymous", "authenticated")

# Keys hashed into the STATE ID, and the chaining keys that never are.
CONTENT_KEYS = (
    "state_version", "access_class", "surface_digest",
    "tools", "prompts", "resources", "instructions_digest",
)
ID_EXCLUDED_KEYS = ("state_id", "previous_state_id")
LIST_KEYS = ("tools", "prompts", "resources")
_SURFACE_FIELDS = (("tools", "name"), ("prompts", "name"), ("resources", "uri"))
_DIGEST_KEYS = ("surface_digest", "instructions_digest")


def canonical_json(obj) -> str:
    """The one canonical serialization: surface.compact (sorted keys,
    separators ',' and ':', ensure_ascii=True)."""
    return _surface.compact(obj)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_hex64(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _check_shape(state) -> None:
    """Structural checks. Every ValueError names the offending key."""
    if not isinstance(state, dict):
        raise ValueError("state must be a JSON object")
    for key in sorted(state):
        if key not in CONTENT_KEYS and key not in ID_EXCLUDED_KEYS:
            raise ValueError(f"unknown key: {key}")
    for key in CONTENT_KEYS:
        if key not in state:
            raise ValueError(f"missing key: {key}")
    if state["state_version"] != STATE_VERSION:
        raise ValueError(f"state_version: expected {STATE_VERSION!r}, got {state['state_version']!r}")
    if state["access_class"] not in ACCESS_CLASSES:
        raise ValueError(f"access_class: must be one of {', '.join(ACCESS_CLASSES)}")
    for key in LIST_KEYS:
        value = state[key]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{key}: must be a list of strings")
        if value != sorted(value):
            raise ValueError(f"{key}: list is not sorted")
    for key in _DIGEST_KEYS:
        if not _is_hex64(state[key]):
            raise ValueError(f"{key}: must be 64 lowercase hex characters")
    for key in ID_EXCLUDED_KEYS:
        if key in state and state[key] is not None and not _is_hex64(state[key]):
            raise ValueError(f"{key}: must be 64 lowercase hex characters or null")


def id_preimage(state: dict) -> str:
    """The canonical JSON string hashed to form the STATE ID."""
    _check_shape(state)
    return canonical_json({k: state[k] for k in CONTENT_KEYS})


def compute_state_id(state: dict) -> str:
    """STATE ID: sha256 hex of the canonical JSON of the state without
    state_id / previous_state_id."""
    return _sha256_hex(id_preimage(state))


def validate_state(state: dict) -> dict:
    """Raise ValueError naming the key unless state conforms; return it.

    A state_id that is present must match the content.
    """
    expected = compute_state_id(state)
    if state.get("state_id") is not None and state["state_id"] != expected:
        raise ValueError(f"state_id: does not match content (expected {expected})")
    return state


def _identifiers(items, field):
    """Sorted identifiers of the object items carrying a string ``field``.

    Other items contribute nothing here but are still covered by
    surface_digest. Duplicates are kept.
    """
    return sorted(
        item[field] for item in items or []
        if isinstance(item, dict) and isinstance(item.get(field), str)
    )


def build_state(surface: dict, access_class: str) -> dict:
    """Build the security state for a captured surface at one access class."""
    if access_class not in ACCESS_CLASSES:
        raise ValueError(f"access_class: must be one of {', '.join(ACCESS_CLASSES)}")
    surface = surface or {}
    state = {
        "state_version": STATE_VERSION,
        "access_class": access_class,
        "surface_digest": _surface.surface_digest(surface),
    }
    for key, field in _SURFACE_FIELDS:
        state[key] = _identifiers(surface.get(key), field)
    state["instructions_digest"] = _sha256_hex(surface.get("instructions") or "")
    state["state_id"] = compute_state_id(state)
    return state


_DEFAULT_PORTS = {"http": 80, "https": 443}


def normalize_target(url: str) -> str:
    """Normalize a target URL (observation-v1 / passport target field).

    Lowercase scheme and host, drop the default port, keep the path,
    drop query, fragment and userinfo.
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
