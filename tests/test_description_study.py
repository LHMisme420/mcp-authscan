import copy
import importlib.util
import json
from pathlib import Path

from mcp_authscan import description_probe

_spec = importlib.util.spec_from_file_location(
    "description_study", Path(__file__).resolve().parents[1] / "tools" / "description_study.py")
ds = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ds)

TOOLS = [{"name": "echo", "description": "Echo the input back."}]


def _raw(keys):
    # values carry severity/verdict columns the runner must never read
    return json.dumps({"findings": {k: [{"severity": "CRITICAL", "verdict": "VULN"}] for k in keys}}).encode()


def _prober(seen):
    def probe(target):
        seen.append(target)
        return description_probe.grade(TOOLS, target)
    return probe


def _entry(keys, resolver=lambda h: True, seen=None):
    return ds.build_entry(_raw(keys), resolver=resolver, prober=_prober(seen if seen is not None else []),
                          workers=2, version="0.0.0+test", probe_set="test", now="2026-11-28T00:00:00+00:00",
                          study_id="desc-study-test")


def test_unresolvable_host_is_excluded_not_graded():
    seen = []
    e = _entry(["ok.example/mcp", "nx.invalid/mcp"], resolver=lambda h: h != "nx.invalid", seen=seen)
    assert seen == ["https://ok.example/mcp"]
    assert e["resolved_count"] == 1 and e["skipped_count"] == 1
    assert e["skipped"] == [{"target": "https://nx.invalid/mcp", "reason": "dns"}]
    assert e["skipped_reasons"] == {"dns": 1}
    assert [t["target"] for t in e["targets"]] == ["https://ok.example/mcp"]
    assert "severity" not in json.dumps(e["skipped"]) and "VULN" not in json.dumps(e)


def test_duplicate_keys_collapse_to_one_target():
    seen = []
    e = _entry(["Host.example/mcp", "host.example/mcp/", "https://host.example/mcp", "host.example:443/mcp"],
               seen=seen)
    assert e["key_count"] == 4 and e["target_count"] == 1
    assert seen == ["https://host.example/mcp"]


def test_study_hash_changes_when_one_row_flips():
    e = _entry(["a.example/mcp", "b.example/mcp"])
    assert ds.rows_hash(e["targets"]) == e["rows_hash"]
    flipped = copy.deepcopy(e["targets"])
    row = flipped[1]["rows"][0]
    row["status"] = "FLAGGED" if row["status"] != "FLAGGED" else "CLEAN"
    assert ds.rows_hash(flipped) != e["rows_hash"]
    assert "16,072 registry walk" in e["statement"] and "not" in e["statement"]
