"""Surface state (state_version "1"): build_state / load_state / surface_state_id."""
import copy
import hashlib
import json

import pytest

from mcp_authscan.evidence.state import build_state, load_state, surface_state_id
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
EXPECTED_ID = "61791e9f028e4d10a294d6bded1947974e218b848c98c1fc7ed224837309949f"


def test_fixed_surface_literal_id():
    state = build_state(SURFACE)
    assert state == {
        "state_version": "1",
        "surface_digest": "97b21b2bd8b9057e5e6196bad5bac627dfab07ae9ab780f5a570d17429c2a186",
        "tools": ["list_docs", "write_doc"],
        "prompts": ["summarize"],
        "resources": ["file:///docs/a.md", "file:///docs/b.md"],
        "instructions_digest": "09dc366d4fe480877cf5660c3c51300f9927e11ab16cda93bbbbd6c651c6ee61",
        "state_id": EXPECTED_ID,
    }


def test_id_is_sha256_of_compact_object_without_id():
    state = build_state(SURFACE)
    body = {k: v for k, v in state.items() if k != "state_id"}
    preimage = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert hashlib.sha256(preimage.encode("utf-8")).hexdigest() == EXPECTED_ID
    assert surface_state_id(state) == EXPECTED_ID


def test_no_timestamp_target_or_coverage():
    assert set(build_state(SURFACE)) == {
        "state_version", "surface_digest", "tools", "prompts", "resources", "instructions_digest", "state_id"}


def test_reordered_input_same_id():
    shuffled = copy.deepcopy(SURFACE)
    for key in ("tools", "prompts", "resources"):
        shuffled[key].reverse()
    shuffled["tools"][0] = dict(reversed(list(shuffled["tools"][0].items())))
    shuffled = dict(reversed(list(shuffled.items())))
    assert build_state(shuffled)["state_id"] == EXPECTED_ID


def test_tool_added_changes_id():
    added = copy.deepcopy(SURFACE)
    added["tools"].append({"name": "delete_doc", "description": "Delete", "inputSchema": {"type": "object"}})
    state = build_state(added)
    assert state["tools"] == ["delete_doc", "list_docs", "write_doc"]
    assert state["state_id"] != EXPECTED_ID


def test_tool_removed_changes_id():
    removed = copy.deepcopy(SURFACE)
    removed["tools"] = [t for t in removed["tools"] if t["name"] != "write_doc"]
    state = build_state(removed)
    assert state["tools"] == ["list_docs"]
    assert state["state_id"] != EXPECTED_ID


def test_description_change_moves_surface_digest_and_id():
    edited = copy.deepcopy(SURFACE)
    edited["tools"][0]["description"] = "Write a document and email it"
    state = build_state(edited)
    assert state["tools"] == ["list_docs", "write_doc"]
    assert state["surface_digest"] == surface_digest(edited) != build_state(SURFACE)["surface_digest"]
    assert state["state_id"] != EXPECTED_ID


def test_load_roundtrip():
    state = build_state(SURFACE)
    assert load_state(json.loads(json.dumps(state))) == state


def test_load_rejects_unknown_key_naming_it():
    state = dict(build_state(SURFACE), captured_at="2026-11-18T00:00:00Z")
    with pytest.raises(ValueError, match="captured_at"):
        load_state(state)


@pytest.mark.parametrize("key", ["tools", "prompts", "resources"])
def test_load_rejects_unsorted_list_naming_key(key):
    state = build_state(SURFACE)
    state[key] = ["zzz", "aaa"]
    with pytest.raises(ValueError, match=key):
        load_state(state)


@pytest.mark.parametrize("key", ["state_version", "surface_digest", "tools", "instructions_digest", "state_id"])
def test_load_rejects_missing_key_naming_it(key):
    state = build_state(SURFACE)
    del state[key]
    with pytest.raises(ValueError, match=key):
        load_state(state)


def test_load_rejects_tampered_content():
    state = build_state(SURFACE)
    state["tools"] = ["list_docs"]
    with pytest.raises(ValueError, match="state_id"):
        load_state(state)
