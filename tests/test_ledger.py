"""boundary-ledger-v1: append-only, one per target and access class."""
import copy
import json

import pytest

from mcp_authscan.evidence.ledger import append_entry, append_observation, make_header, read_ledger, verify_ledger
from mcp_authscan.evidence.state import build_state, compute_state_id

TARGET = "https://mcp.example.com/mcp"


def _surface(*tools):
    return {"instructions": "", "tools": [{"name": t} for t in tools], "prompts": [], "resources": []}


def _obs(state, target=TARGET):
    state = dict(state)
    return {
        "schema": "observation-v1", "target": target, "state_id": compute_state_id(state), "state": state,
        "observed_at": {"start": "2026-11-18T20:00:00Z", "end": "2026-11-18T20:00:01Z"},
        "scanner": {"name": "mcp-authscan", "version": "t", "probe_set_version": "t"},
        "coverage": {"in_scope": 0, "pass": 0, "fail": 0, "not_observed": 0, "excluded": 0},
        "not_observed": [], "excluded": [],
    }


A = build_state(_surface("list_docs"), "anonymous")
B = build_state(_surface("list_docs", "write_doc"), "anonymous")


def test_append_chain_and_verify(tmp_path):
    path = tmp_path / "anon.jsonl"
    first = append_observation(path, _obs(A))
    second = append_observation(path, _obs(B))
    assert first["previous_state_id"] is None and first["state_id"] == A["state_id"]
    assert second["previous_state_id"] == A["state_id"] and second["state_id"] == B["state_id"]
    lines = read_ledger(path)
    assert lines[0] == {"schema": "boundary-ledger-v1", "target": TARGET, "access_class": "anonymous"}
    assert verify_ledger(lines) == B["state_id"]


def test_same_state_as_head_is_a_noop(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A))
    before = path.read_text()
    assert append_observation(path, _obs(A)) is None
    assert path.read_text() == before


def test_revert_is_a_new_entry(tmp_path):
    path = tmp_path / "anon.jsonl"
    for state in (A, B, A):
        append_observation(path, _obs(state))
    assert [e["state_id"] for e in read_ledger(path)[1:]] == [A["state_id"], B["state_id"], A["state_id"]]


def test_refuses_different_target(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A))
    before = path.read_text()
    with pytest.raises(ValueError, match="target"):
        append_observation(path, _obs(B, target="https://other.example.com/mcp"))
    assert path.read_text() == before


def test_refuses_different_access_class(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A))
    before = path.read_text()
    with pytest.raises(ValueError, match="access_class"):
        append_observation(path, _obs(build_state(_surface("list_docs"), "authenticated")))
    assert path.read_text() == before


def test_refuses_invalid_observation():
    bad = _obs(A)
    bad["state_id"] = "0" * 64
    with pytest.raises(ValueError, match="state_id"):
        append_entry([make_header(TARGET, "anonymous")], bad)


def _lines():
    lines = [make_header(TARGET, "anonymous")]
    for state in (A, B):
        lines.append(append_entry(lines, _obs(state)))
    return lines


@pytest.mark.parametrize("tamper, where", [
    (lambda ls: ls[1].update(tools=["delete_doc"]), "line 2"),
    (lambda ls: ls[2].update(previous_state_id=None), "line 3"),
    (lambda ls: ls.insert(1, ls.pop(2)), "line 2"),
    (lambda ls: ls.append(copy.deepcopy(ls[2])), "line 4"),
    (lambda ls: ls[0].update(access_class="authenticated"), "line 2"),
    (lambda ls: ls[0].update(target="HTTPS://MCP.example.com/mcp"), "line 1"),
    (lambda ls: ls.pop(0), "line 1"),
])
def test_offline_verification_detects_tampering(tamper, where):
    lines = _lines()
    assert verify_ledger(lines) == B["state_id"]
    tamper(lines)
    with pytest.raises(ValueError, match=where):
        verify_ledger(lines)


def test_truncation_is_not_detected_by_design():
    # boundary-ledger-v1 §5: cutting entries off the end leaves a valid ledger.
    lines = _lines()[:-1]
    assert verify_ledger(lines) == A["state_id"]


def test_file_is_jsonl_header_first(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A))
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["schema"] == "boundary-ledger-v1" and rows[1]["state_id"] == A["state_id"]
