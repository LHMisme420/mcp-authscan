"""matrix.json must not grade token_response_iss: the spec puts the issuer check on the authorization response."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_token_response_iss_is_never_graded():
    rows = json.loads((ROOT / "matrix.json").read_text())
    assert rows, "matrix.json is empty"
    for row in rows:
        assert row["token_response_iss"] == "NOT_REQUIRED", row


def test_tokencell_cannot_write_a_grade():
    src = (ROOT / "mcp_authscan" / "conformance_tokencell.py").read_text()
    assert 'verdict = "NOT_REQUIRED"' in src
