"""Verdict/exit-code regression tests for the client-side issuer-binding check.

These pin the three outcomes of ``mcp_authscan.client_check.run``:

    FAIL     (exit 1) a client that hands credentials to a mismatched issuer
    PASS     (exit 0) a client that refuses on issuer mismatch
    EXCLUDED (exit 2) the check could not be exercised; the cause is named

FAIL/PASS need the two pinned client interpreters. Their paths come from env
vars so a CI matrix can point them wherever it installs each version; they
default to the local ``~/venv-fm411`` / ``~/venv-fm412`` layout and the test
skips (rather than fails) when an interpreter is absent. EXCLUDED needs only an
interpreter with no MCP client library, for which the interpreter running the
tests serves perfectly.
"""
import json
import os
import sys

import pytest

from mcp_authscan import client_check

FM411 = os.environ.get(
    "CLIENT_CHECK_FM411", os.path.expanduser("~/venv-fm411/bin/python")
)
FM412 = os.environ.get(
    "CLIENT_CHECK_FM412", os.path.expanduser("~/venv-fm412/bin/python")
)
EXPECTED_ISSUER = "https://expected.invalid"

_SECRETS = ("probe-secret", "decoy-token")


def _run(capsys, client_python, name, expect_issuer):
    """Call run(), returning (exit_code, parsed_report, raw_stdout)."""
    code = client_check.run(client_python, name, expect_issuer)
    out = capsys.readouterr().out
    return code, json.loads(out), out


def _no_raw_secret(raw):
    return all(secret not in raw for secret in _SECRETS)


def test_excluded_when_client_lib_absent(capsys):
    # The interpreter running pytest has mcp_authscan but no fastmcp/mcp client
    # library, so the provider import fails inside the child.
    code, report, raw = _run(capsys, sys.executable, "no-client-lib", None)
    assert code == 2
    assert report["verdict"] == "EXCLUDED"
    assert "child stderr" in report["reason"]
    assert report["captured"] == []


@pytest.mark.skipif(not os.path.exists(FM411), reason="fm411 interpreter not present")
def test_fail_on_client_without_issuer_binding(capsys):
    code, report, raw = _run(capsys, FM411, "fastmcp-4.1.1", None)
    assert code == 1
    assert report["verdict"] == "FAIL"
    # A /token POST carrying an Authorization header is the credential leak.
    token_rows = [
        row for row in report["captured"]
        if (row["path"] or "").split("?")[0] == "/token" and row["authorization"]
    ]
    assert token_rows, "expected a captured /token row with an Authorization header"
    # Authorization must be redacted (first-five/last-four), never raw.
    assert "..." in token_rows[0]["authorization"]
    assert _no_raw_secret(raw), "raw secret/token leaked into the report"


@pytest.mark.skipif(not os.path.exists(FM412), reason="fm412 interpreter not present")
def test_pass_on_client_with_issuer_binding(capsys):
    code, report, raw = _run(capsys, FM412, "fastmcp-4.1.2", EXPECTED_ISSUER)
    assert code == 0
    assert report["verdict"] == "PASS"
    # The client read discovery metadata...
    assert any("oauth-protected-resource" in t for t in report["touches"])
    # ...and never touched the token endpoint.
    token_rows = [
        row for row in report["captured"]
        if (row["path"] or "").split("?")[0] == "/token"
    ]
    assert not token_rows, "client unexpectedly contacted the token endpoint"
    assert _no_raw_secret(raw)


def test_redact_keeps_five_and_four():
    assert client_check.redact("Basic QUJDREVGR0hJSg==") == "Basic...Sg=="
    assert client_check.redact("short") == "*****"
    assert client_check.redact(None) is None
