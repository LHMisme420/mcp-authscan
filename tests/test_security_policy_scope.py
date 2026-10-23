"""SECURITY.md must describe the tool that actually runs.

SECURITY.md said "mcp-authscan is a static analysis tool. It reads target source
code and emits findings; it does not execute target code." Reading source is one
mode, but the shipped `mcp-authscan` command scans *live* servers: it POSTs an
MCP initialize request, follows the RFC 9728 -> RFC 8414 discovery chain, and
runs OAuth probes (token endpoint, PKCE, redirect-uri, client-auth, CORS)
against the host the operator names. It sends probe traffic over HTTP(S).

That matters for the policy, not just the prose: someone deciding whether to
report a scanner-side bug reads the scope section. A reader who is told the tool
only reads source will not report that discovery fetched a URL the target
supplied, or that a redirect was followed to an internal address - both of which
are scanner-behaviour bugs this file is supposed to invite.

These assertions are deliberately semantic rather than literal so the wording
can be edited freely as long as the claims stay true.
"""
from pathlib import Path

SECURITY_MD = Path(__file__).resolve().parents[1] / "SECURITY.md"


def _scope_text() -> str:
    return SECURITY_MD.read_text(encoding="utf-8")


def test_scope_does_not_claim_static_analysis_only():
    text = _scope_text().lower()
    assert "static analysis tool" not in text, (
        "SECURITY.md still describes the scanner as a static analysis tool"
    )
    # The live mode must be described as sending traffic to a named target.
    assert "probe" in text, "SECURITY.md does not mention the scanner's probe traffic"
    assert "http" in text, "SECURITY.md does not mention live HTTP(S) scanning"


def test_scope_keeps_the_true_non_execution_claim():
    """The scanner really does not execute target code - keep saying so."""
    assert "does not execute target code" in _scope_text().lower()


def test_scope_makes_scanner_network_behaviour_reportable():
    """Scanner-side egress/request handling must be explicitly in scope."""
    text = _scope_text().lower()
    assert "in scope" in text
    assert "request" in text, (
        "scanner request handling is not named as in scope"
    )


def test_disclosure_channel_is_unchanged():
    """The security contact is the whole point of the file; never lose it."""
    assert "lhmisme2011@gmail.com" in _scope_text()
