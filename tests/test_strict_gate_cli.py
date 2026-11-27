"""mcp-authscan-gate: only CLEAN exits 0; CONDITIONAL exits 2; anything else exits 1."""
import tomllib
from pathlib import Path

import pytest

from mcp_authscan import strict_gate

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("pyproject", ["pyproject.toml", "mcp_authscan/pyproject.toml"])
def test_gate_console_script_declared(pyproject):
    scripts = tomllib.loads((ROOT / pyproject).read_text())["project"]["scripts"]
    assert scripts["mcp-authscan-gate"] == "mcp_authscan.strict_gate:main"


@pytest.mark.parametrize("verdict,code", [("CLEAN", 0), ("CONDITIONAL", 2), ("REJECT", 1), ("CONTRADICTED", 1)])
def test_gate_exit_codes(monkeypatch, capsys, verdict, code):
    monkeypatch.setattr(strict_gate, "evaluate", lambda *a, **k: {"verdict": verdict, "check": "X", "detail": ""})
    assert strict_gate.main(["r.json", "p.json", "k.json"]) == code


def test_gate_error_is_reject(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("x")
    monkeypatch.setattr(strict_gate, "evaluate", boom)
    assert strict_gate.main(["r.json", "p.json", "k.json"]) == 1
    assert '"GATE-ERROR"' in capsys.readouterr().out
