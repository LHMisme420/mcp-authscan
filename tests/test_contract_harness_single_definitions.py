"""tests/test_verdict_contract.py defines start_fixture once (a second def silently replaced the first)."""
import ast
from pathlib import Path

HARNESS = Path(__file__).resolve().parent / "test_verdict_contract.py"


def test_start_fixture_is_defined_once():
    tree = ast.parse(HARNESS.read_text(encoding="utf-8"))
    lines = [n.lineno for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "start_fixture"]
    assert len(lines) == 1, "start_fixture defined at lines %s" % lines
