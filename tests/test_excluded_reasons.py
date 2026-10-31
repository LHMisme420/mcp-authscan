"""EXCLUDED probes are printed with their reason (PROBE_CONTRACT.md "Summary wording for EXCLUDED",
[5] jwks-keys). Fixture branch JWKS=absent: metadata without jwks_uri. Local fixture only."""
from mcp_authscan.oauth_probes_v2 import probe_jwks_keys
from mcp_authscan.report_copy import render_summary
from tests.test_dcr_client_source import _cli, scope  # noqa: F401 (autouse fixture)
from tests.test_probes_pkce_redirect import fixture


def test_no_jwks_uri_is_excluded_with_named_limitation():
    r = probe_jwks_keys(None)
    assert r.status == "EXCLUDED" and r.limitation == "No JWKS endpoint"


def test_summary_lists_each_excluded_reason():
    lines = render_summary([probe_jwks_keys(None)])
    i = lines.index("EXCLUDED (1, prerequisite missing, never sent):")
    assert lines[i + 1] == "  jwks-keys: No JWKS endpoint"


def test_cli_prints_jwks_reason_when_no_jwks_uri():
    with fixture(JWKS="absent") as base:
        proc = _cli(base)
    assert "[5] jwks-keys            EXCLUDED" in proc.stderr
    out = proc.stdout.splitlines()
    i = next(j for j, line in enumerate(out) if line.startswith("EXCLUDED (") and "prerequisite missing" in line)
    assert "  jwks-keys: No JWKS endpoint" in out[i + 1:]


def test_cli_prints_client_probe_reasons_when_registration_refused():
    with fixture(REDIRECT_HOSTS="none") as base:
        out = _cli(base).stdout
    assert ("  pkce-s256: No client_id to build an authorization request (MCPAUTHSCAN_CLIENT_ID not set); "
            "Dynamic client registration unavailable: registration refused every redirect candidate: "
            "HTTP 400 error=invalid_redirect_uri") in out


def test_jwks_fetch_failure_is_not_observed(monkeypatch):
    from urllib.error import URLError
    from mcp_authscan import oauth_probes_v2

    def boom(*args, **kwargs):
        raise URLError("connection refused")

    monkeypatch.setattr(oauth_probes_v2, "_egress_guard", boom)
    r = probe_jwks_keys("http://127.0.0.1:9/jwks")
    assert r.status == "NOT_OBSERVED"
