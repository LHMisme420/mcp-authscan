"""security-state-v1 built from a surface: literal id, order independence, sensitivity."""
import copy
import hashlib
import json

import pytest

from mcp_authscan.evidence.state import build_state, compute_state_id, validate_state
from mcp_authscan.surface import surface_digest

SURFACE = {
    "instructions": "Use list_docs before write_doc.",
    "tools": [
        {"name": "write_doc", "description": "Write a document", "inputSchema": {"type": "object"}},
        {"name": "list_docs", "description": "List documents", "inputSchema": {"type": "object"}},
    ],
    "prompts": [{"name": "summarize", "description": "Summarize a doc"}],
    "resources": [{"uri": "file:///docs/b.md", "name": "b"}, {"uri": "file:///docs/a.md", "name": "a"}],
}
EXPECTED_ID = "b1208b5f7f7bc9efc82553a985da05d9a241a5d1e3cd3fbd858968c9bf0ec477"


def test_fixed_surface_literal_id():
    assert build_state(SURFACE, "anonymous") == {
        "state_version": "1",
        "access_class": "anonymous",
        "surface_digest": "97b21b2bd8b9057e5e6196bad5bac627dfab07ae9ab780f5a570d17429c2a186",
        "tools": ["list_docs", "write_doc"],
        "prompts": ["summarize"],
        "resources": ["file:///docs/a.md", "file:///docs/b.md"],
        "instructions_digest": "09dc366d4fe480877cf5660c3c51300f9927e11ab16cda93bbbbd6c651c6ee61",
        "state_id": EXPECTED_ID,
    }


def test_id_is_sha256_of_compact_object_without_id():
    state = build_state(SURFACE, "anonymous")
    body = {k: v for k, v in state.items() if k != "state_id"}
    preimage = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert hashlib.sha256(preimage.encode("utf-8")).hexdigest() == EXPECTED_ID == compute_state_id(state)


def test_no_timestamp_target_or_coverage():
    assert set(build_state(SURFACE, "anonymous")) == {
        "state_version", "access_class", "surface_digest", "tools", "prompts", "resources",
        "instructions_digest", "state_id"}


def test_reordered_input_same_id():
    shuffled = copy.deepcopy(SURFACE)
    for key in ("tools", "prompts", "resources"):
        shuffled[key].reverse()
    shuffled["tools"][0] = dict(reversed(list(shuffled["tools"][0].items())))
    shuffled = dict(reversed(list(shuffled.items())))
    assert build_state(shuffled, "anonymous")["state_id"] == EXPECTED_ID


def test_tool_added_changes_id():
    added = copy.deepcopy(SURFACE)
    added["tools"].append({"name": "delete_doc", "description": "Delete", "inputSchema": {"type": "object"}})
    state = build_state(added, "anonymous")
    assert state["tools"] == ["delete_doc", "list_docs", "write_doc"]
    assert state["state_id"] != EXPECTED_ID


def test_tool_removed_changes_id():
    removed = copy.deepcopy(SURFACE)
    removed["tools"] = [t for t in removed["tools"] if t["name"] != "write_doc"]
    state = build_state(removed, "anonymous")
    assert state["tools"] == ["list_docs"]
    assert state["state_id"] != EXPECTED_ID


def test_access_class_changes_id():
    assert build_state(SURFACE, "authenticated")["state_id"] != EXPECTED_ID


def test_description_change_moves_surface_digest_and_id():
    edited = copy.deepcopy(SURFACE)
    edited["tools"][0]["description"] = "Write a document and email it"
    state = build_state(edited, "anonymous")
    assert state["tools"] == ["list_docs", "write_doc"]
    assert state["surface_digest"] == surface_digest(edited) != build_state(SURFACE, "anonymous")["surface_digest"]
    assert state["state_id"] != EXPECTED_ID


def test_build_requires_known_access_class():
    with pytest.raises(ValueError, match="access_class"):
        build_state(SURFACE, "admin")


def test_roundtrip_through_json_validates():
    state = build_state(SURFACE, "anonymous")
    assert validate_state(json.loads(json.dumps(state))) == state


def test_rejects_unknown_key_naming_it():
    with pytest.raises(ValueError, match="captured_at"):
        validate_state(dict(build_state(SURFACE, "anonymous"), captured_at="2026-11-18T00:00:00Z"))


@pytest.mark.parametrize("key", ["tools", "prompts", "resources"])
def test_rejects_unsorted_list_naming_key(key):
    state = build_state(SURFACE, "anonymous")
    state[key] = ["zzz", "aaa"]
    with pytest.raises(ValueError, match=key):
        validate_state(state)


def test_rejects_tampered_content():
    state = build_state(SURFACE, "anonymous")
    state["tools"] = ["list_docs"]
    with pytest.raises(ValueError, match="state_id"):
        validate_state(state)
