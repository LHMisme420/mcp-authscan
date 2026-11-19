"""observation-v1 verification (schemas/observation-v1.md §5)."""
import copy

import pytest

from mcp_authscan.evidence.observation import verify_observation
from mcp_authscan.evidence.state import build_state

SURFACE = {"instructions": "", "tools": [{"name": "list_docs"}], "prompts": [], "resources": []}


def _obs():
    state = build_state(SURFACE, "anonymous")
    return {
        "schema": "observation-v1",
        "target": "https://mcp.example.com/mcp",
        "state_id": state["state_id"],
        "state": state,
        "observed_at": {"start": "2026-11-18T20:00:00Z", "end": "2026-11-18T20:00:05Z"},
        "scanner": {"name": "mcp-authscan", "version": "1.1.24", "probe_set_version": "2026.11.16.1"},
        "coverage": {"in_scope": 3, "pass": 1, "fail": 1, "not_observed": 1, "excluded": 1},
        "not_observed": [{"probe_id": "5:jwks-keys", "reason": "HTTP 502", "affects": []}],
        "excluded": [{"probe_id": "11:token-audience", "missing_prerequisite": "no client credential"}],
        "report_hash": "ab" * 32,
    }


def test_valid_observation_passes():
    verify_observation(_obs())


def test_envelope_changes_do_not_move_state_id():
    a, b = _obs(), _obs()
    b.update(target="https://other.example.com/mcp", observed_at={"start": "2027-01-01T00:00:00Z", "end": "2027-01-01T00:00:01Z"})
    b["scanner"]["version"] = "9.9.9"
    verify_observation(b)
    assert a["state_id"] == b["state_id"]


@pytest.mark.parametrize("tamper", [
    lambda o: o.update(schema="observation-v2"),
    lambda o: o.update(target="HTTPS://MCP.example.com:443/mcp"),
    lambda o: o.update(state_id="0" * 64),
    lambda o: o["state"].update(tools=["delete_doc"]),
    lambda o: o["coverage"].update(in_scope=99),
    lambda o: o["coverage"].update(not_observed=2, in_scope=4),
    lambda o: o["observed_at"].update(end="2000-01-01T00:00:00Z"),
    lambda o: o["observed_at"].update(start="2026-11-18 20:00:00"),
    lambda o: o["scanner"].update(version=""),
    lambda o: o["excluded"][0].pop("missing_prerequisite"),
])
def test_tampering_rejected(tamper):
    obs = copy.deepcopy(_obs())
    tamper(obs)
    with pytest.raises(ValueError):
        verify_observation(obs)
