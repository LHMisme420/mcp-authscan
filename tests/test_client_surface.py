import json
from mcp_authscan import client_surface


def test_verdict_passes_through(monkeypatch):
    def fake_run(*a, **k):
        print(json.dumps({
            "kind": "python",
            "client": "x",
            "verdict": "FAIL",
            "reason": "credential sent",
            "touches": ["POST /token"],
            "captured": [],
        }))
        return 1
    monkeypatch.setattr(client_surface.client_check, "run", fake_run)
    rec = client_surface.assess("/usr/bin/python3")
    assert rec["surface"] == "client"
    assert rec["verdict"] == "FAIL"
    assert rec["code"] == 1
    assert "prerequisite" not in rec


def test_excluded_names_prerequisite(monkeypatch):
    def fake_run(*a, **k):
        print(json.dumps({
            "kind": "python",
            "client": "x",
            "verdict": "EXCLUDED",
            "reason": "SDK not installed",
            "touches": [],
            "captured": [],
        }))
        return 2
    monkeypatch.setattr(client_surface.client_check, "run", fake_run)
    rec = client_surface.assess("/usr/bin/python3")
    assert rec["verdict"] == "EXCLUDED"
    assert rec["prerequisite"] == "SDK not installed"
