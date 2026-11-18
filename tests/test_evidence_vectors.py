"""The test vectors printed in schemas/*.md, checked against the implementation.

Vectors are parsed out of the Markdown, so the spec and the code cannot drift apart silently.
"""
import copy
import hashlib
import json
import re
from pathlib import Path

import pytest

from mcp_authscan.evidence.delta import compute_delta
from mcp_authscan.evidence.state import canonical_json, compute_state_id, id_preimage, normalize_target

SCHEMAS = Path(__file__).resolve().parents[1] / "schemas"
STATE_MD = (SCHEMAS / "security-state-v1.md").read_text(encoding="utf-8")
DELTA_MD = (SCHEMAS / "boundary-delta-v1.md").read_text(encoding="utf-8")


def _block(md, after, lang):
    m = re.search(re.escape(after) + r".*?```" + lang + r"\n(.*?)```", md, re.S)
    assert m, f"vector after {after!r} not found"
    return m.group(1)


STATE = json.loads(_block(STATE_MD, "Input state:", "json"))
PREIMAGE = _block(STATE_MD, "Canonical preimage", "").strip()
STATE_ID = _block(STATE_MD, "STATE ID:\n", "").strip()
DELTA = json.loads(_block(DELTA_MD, "## 5. Test vector", "json"))


def test_canonical_preimage_matches_spec():
    assert id_preimage(STATE) == PREIMAGE


def test_state_id_matches_spec_and_plain_sha256():
    assert compute_state_id(STATE) == STATE_ID
    assert hashlib.sha256(PREIMAGE.encode("ascii")).hexdigest() == STATE_ID


def test_chaining_keys_excluded_from_state_id():
    chained = dict(STATE, state_id=STATE_ID, previous_state_id=None)
    assert compute_state_id(chained) == STATE_ID
    chained["previous_state_id"] = "0" * 64
    assert compute_state_id(chained) == STATE_ID


def test_escaping_vector():
    assert canonical_json({"b": "é \n/", "a": "\U0001F600"}) == '{"a":"\\ud83d\\ude00","b":"\\u00e9\\u2028\\n/"}'


@pytest.mark.parametrize("mutate", [
    lambda s: s.update(extra=1),
    lambda s: s["cors"].update(extra=1),
    lambda s: s["tool_visibility"].update(authenticated_tools=["write_doc", "delete_doc"]),
    lambda s: s["tool_visibility"].update(authenticated_tools=["a", "a"]),
    lambda s: s["audience"].pop("enforced"),
    lambda s: s["audience"].update(enforced="yes"),
    lambda s: s.update(schema="security-state-v2"),
    lambda s: s.update(state_id="NOTHEX"),
])
def test_invalid_states_rejected_not_normalized(mutate):
    bad = copy.deepcopy(STATE)
    mutate(bad)
    with pytest.raises(ValueError):
        compute_state_id(bad)


def _curr():
    curr = copy.deepcopy(STATE)
    curr["tool_visibility"]["unauthenticated_tools"] = ["delete_doc", "list_docs"]
    return curr


def test_delta_vector_matches_spec():
    assert canonical_json(compute_delta(STATE, _curr())) == canonical_json(DELTA)


def test_compensated_vector():
    curr = _curr()
    curr["origin"]["allowed_origins"] = []
    d = compute_delta(STATE, curr)
    assert (d["classification"], d["rule"], d["compensating_tightening"]) == ("EXPOSURE_COMPENSATED", "BD-R2", ["origin"])


def test_swap_is_regression():
    curr = copy.deepcopy(STATE)
    curr["tool_visibility"]["unauthenticated_tools"] = ["write_doc"]
    assert compute_delta(STATE, curr)["classification"] == "AUTHORIZATION_REGRESSION"


def test_mixed_dimension_does_not_compensate():
    curr = _curr()
    curr["cors"]["allow_credentials"] = True       # loosen
    curr["cors"]["allowed_origins"] = []           # tighten
    d = compute_delta(STATE, curr)
    assert d["dimensions"]["cors"]["tightened"] is False
    assert d["classification"] == "AUTHORIZATION_REGRESSION"


def test_null_transition_does_not_compensate():
    curr = _curr()
    curr["origin"]["allowed_origins"] = None
    assert compute_delta(STATE, curr)["classification"] == "AUTHORIZATION_REGRESSION"


@pytest.mark.parametrize("change, expected", [
    (lambda s: None, "NO_CHANGE"),
    (lambda s: s["cors"].update(allow_origin_wildcard=True), "BOUNDARY_LOOSENED"),
    (lambda s: s["cors"].update(allow_credentials=None), "INDETERMINATE"),
    (lambda s: s["tool_visibility"].update(unauthenticated_tools=None), "INDETERMINATE"),
    (lambda s: s["tool_visibility"].update(unauthenticated_tools=[]), "BOUNDARY_TIGHTENED"),
    (lambda s: s["tool_visibility"].update(authenticated_tools=["delete_doc", "list_docs", "write_doc", "zz"]),
     "CHANGED_NEUTRAL"),
])
def test_classification_order(change, expected):
    curr = copy.deepcopy(STATE)
    change(curr)
    assert compute_delta(STATE, curr)["classification"] == expected


def test_delta_refuses_cross_target():
    other = dict(copy.deepcopy(STATE), target="https://other.example.com/mcp")
    with pytest.raises(ValueError):
        compute_delta(STATE, other)


@pytest.mark.parametrize("raw, expected", [
    ("HTTPS://MCP.Example.COM:443/mcp?x=1#f", "https://mcp.example.com/mcp"),
    ("http://user:pw@127.0.0.1:80/mcp", "http://127.0.0.1/mcp"),
    ("http://127.0.0.1:9000/MCP", "http://127.0.0.1:9000/MCP"),
    ("https://[::1]:8443/mcp", "https://[::1]:8443/mcp"),
])
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected
