import hashlib
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_authscan.assurance import evaluate

HERE = Path(__file__).parent / "fixtures" / "assurance"
NOW = datetime(2026, 11, 26, 12, tzinfo=timezone.utc)


def raw(report):
    return json.dumps(report, sort_keys=True).encode()


def mock_verifier(data, **_anchor):
    d = json.loads(data)
    ok = d.get("_test_signed") is True
    return {"integrity": {"verdict": "INTACT" if ok else "ALTERED"},
            "authenticity": {"verdict": "SIGNED BY" if ok else "NOT SIGNED"},
            "probe_statuses": {"verdict": "VERIFIED" if ok else "NOT VERIFIED"}}


@pytest.mark.parametrize("name", ["current", "stale", "regressed", "inconclusive"])
def test_fixture_verdict(name):
    fixture = json.loads((HERE / (name + ".json")).read_text())
    reports = [raw(r) for r in fixture["reports"]]
    policy = {"target": "https://example.test/mcp", "max_age_days": fixture["max_age_days"],
              "required_probe_classes": {"authserver": ["issuer-identity"]},
              "require_second_run": fixture["require_second_run"],
              "observations": [{"file_sha256": hashlib.sha256(data).hexdigest(),
                                "observed_at": when} for data, when in zip(reports, fixture["times"])]}
    with patch("mcp_authscan.assurance.verification.verify", side_effect=mock_verifier):
        result = evaluate(policy, reports, now=NOW)
    assert result["verdict"] == fixture["expected"], result
    assert result["prior_report_hash"] == fixture["reports"][0]["report_hash"]
    assert result["policy_sha256"]
    print(f"{name.upper():13} | {result['verdict']:12} | {result['reason']}")


def test_unsigned_never_current():
    f = json.loads((HERE / "current.json").read_text())
    d = f["reports"][0]
    d["_test_signed"] = False
    data = raw(d)
    policy = {"target": d["target"], "max_age_days": 5,
              "required_probe_classes": {"authserver": ["issuer-identity"]},
              "observations": [{"file_sha256": hashlib.sha256(data).hexdigest(),
                                "observed_at": "2026-11-26T11:00:00Z"}]}
    with patch("mcp_authscan.assurance.verification.verify", side_effect=mock_verifier):
        result = evaluate(policy, [data], now=NOW)
    assert result["verdict"] == "INCONCLUSIVE"


def test_tampered_unpinned_report_never_current():
    f = json.loads((HERE / "current.json").read_text())
    original = raw(f["reports"][0]); tampered = raw({**f["reports"][0], "run_started_at": 999})
    policy = {"target": f["reports"][0]["target"], "max_age_days": 5,
              "required_probe_classes": {"authserver": ["issuer-identity"]},
              "observations": [{"file_sha256": hashlib.sha256(original).hexdigest(),
                                "observed_at": "2026-11-26T11:00:00Z"}]}
    with patch("mcp_authscan.assurance.verification.verify", side_effect=mock_verifier):
        result = evaluate(policy, [tampered], now=NOW)
    assert result["verdict"] == "INCONCLUSIVE"
