"""CLI verify: recorded report_hash vs in-process rerun."""
import json
from pathlib import Path

from mcp_authscan.monolith import PROBE_SET_VERSION
from mcp_authscan.report_verify import HASH_SCHEME, HASHED_KEYS
from mcp_authscan import verify


def _minimal_payload():
    data = {
        "target": "http://127.0.0.1:9002/mcp",
        "scan_mode": "LIVE_ENDPOINT_ASSESSMENT",
        "probe_set_version": PROBE_SET_VERSION,
        "probes": [],
        "counts": {},
        "coverage": {},
        "completed": [],
        "not_implemented": [],
        "not_tested": [],
        "scope": "",
        "exit_contract": "",
        "exit_condition": "",
        "exit_code": 0,
        "fail_on": "high",
        "authorization": {},
        "hash_scheme": HASH_SCHEME,
        "findings": [],
        "report_hash": "0" * 64,
    }
    assert set(HASHED_KEYS).issubset(data)
    return data


def test_zeroed_hash_diverges(tmp_path, monkeypatch, capsys):
    payload = _minimal_payload()
    path = Path(tmp_path) / "report.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    def fake_rerun(target, extra_args):
        return json.loads(json.dumps(payload))

    monkeypatch.setattr(verify, "_rerun", fake_rerun)
    rc = verify.main([str(path)])
    out = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert out[0] == "DIVERGENCE"
    assert "report_hash" in out[1].split(",")
