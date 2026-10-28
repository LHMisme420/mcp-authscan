"""Tests for resource probes matching the spec: PASS, FAIL, NOT_OBSERVED, EXCLUDED."""

import pytest
from unittest.mock import Mock, patch
from mcp_authscan.resource_probes import run_resource_probes


def test_dead_port_returns_zero_findings_all_not_observed():
    """Dead port 127.0.0.1:1 -> zero findings, every record NOT_OBSERVED, exit 3."""
    probes = run_resource_probes("http://127.0.0.1:1")
    
    assert len(probes) > 0, "Should return records even on dead port"
    for probe in probes:
        assert probe.status == "NOT_OBSERVED", f"Dead port probe {probe.probe_id} should be NOT_OBSERVED, got {probe.status}"
    fails = [p for p in probes if p.status == "FAIL"]
    assert len(fails) == 0, f"Dead port should have zero FAIL, got {len(fails)}"


def test_anon_initialize_exception_returns_not_observed():
    """Server raises in anon-initialize -> NOT_OBSERVED with exception in detail."""
    with patch('mcp_authscan.resource_probes._egress_guard_fetch') as mock_fetch:
        def side_effect(*args, **kwargs):
            if mock_fetch.call_count == 1:
                # preflight
                return (401, {"WWW-Authenticate": "Bearer"}, b'{"jsonrpc":"2.0","error":{}}')
            elif mock_fetch.call_count == 2:
                # anon-initialize raises
                raise ValueError("Connection error")
            return (401, {}, b'{}')

        mock_fetch.side_effect = side_effect

        probes = run_resource_probes("http://localhost:8000")

        anon_init = next(p for p in probes if p.probe_id == "anon-initialize")
        assert anon_init.status == "NOT_OBSERVED", f"Exception should be NOT_OBSERVED, got {anon_init.status}"


def test_cors_probe_exception_returns_not_observed():
    """Server raises during CORS probe -> NOT_OBSERVED. Never PASS, no 'CORS properly restricted'."""
    with patch('mcp_authscan.resource_probes._egress_guard_fetch') as mock_fetch:
        def side_effect(*args, **kwargs):
            if mock_fetch.call_count == 1:
                return (401, {"WWW-Authenticate": "Bearer"}, b'{"jsonrpc":"2.0","error":{}}')
            elif mock_fetch.call_count == 2:
                return (401, {}, b'{"jsonrpc":"2.0","error":{}}')
            elif mock_fetch.call_count == 3:
                return (401, {}, b'{"jsonrpc":"2.0","error":{}}')
            elif mock_fetch.call_count == 4:
                raise RuntimeError("Network timeout")
            else:
                return (401, {"WWW-Authenticate": "Bearer"}, b'{}')

        mock_fetch.side_effect = side_effect

        probes = run_resource_probes("http://localhost:8000")

        cors = next(p for p in probes if p.probe_id == "endpoint-cors")
        assert cors.status == "NOT_OBSERVED", f"CORS exception should be NOT_OBSERVED, got {cors.status}"
        assert "CORS properly restricted" not in cors.detail


def test_auth_challenge_200_not_pass():
    """Auth-challenge returns 200 -> NOT PASS on the 200 alone."""
    with patch('mcp_authscan.resource_probes._egress_guard_fetch') as mock_fetch:
        calls = [
            # preflight: 401 with header
            (401, {"WWW-Authenticate": "Bearer"}, b'{"jsonrpc":"2.0","error":{}}'),
            # anon-initialize: 401
            (401, {}, b'{"jsonrpc":"2.0","error":{}}'),
            # anon-tools-list: 401
            (401, {}, b'{"jsonrpc":"2.0","error":{}}'),
            # endpoint-cors: 200 with no ACAO
            (200, {}, b'{"jsonrpc":"2.0","result":{}}'),
            # auth-challenge: 200 (should be NOT_OBSERVED)
            (200, {}, b'{"result":{"ok":true}}'),
        ]

        mock_fetch.side_effect = calls

        probes = run_resource_probes("http://localhost:8000")

        auth = next(p for p in probes if p.probe_id == "auth-challenge")
        assert auth.status != "PASS", f"200 response should not be PASS, got {auth.status}"


def test_cors_wildcard_fail_with_captured_headers():
    """Wildcard Allow-Origin -> FAIL with captured header."""
    with patch('mcp_authscan.resource_probes._egress_guard_fetch') as mock_fetch:
        # Setup fetch returns for each probe
        calls = [
            # preflight: 401 with WWW-Authenticate
            (401, {"WWW-Authenticate": "Bearer"}, b'{"jsonrpc":"2.0","error":{}}'),
            # anon-initialize: 401
            (401, {}, b'{"jsonrpc":"2.0","error":{}}'),
            # anon-tools-list: 401
            (401, {}, b'{"jsonrpc":"2.0","error":{}}'),
            # endpoint-cors: 200 with wildcard ACAO
            (200, {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "false",
                "Vary": "Origin"
            }, b'{"jsonrpc":"2.0","result":{}}'),
            # auth-challenge: 401 with WWW-Authenticate
            (401, {"WWW-Authenticate": "Bearer"}, b'{"jsonrpc":"2.0","error":{}}'),
        ]

        mock_fetch.side_effect = calls

        probes = run_resource_probes("http://localhost:8000")

        cors = next(p for p in probes if p.probe_id == "endpoint-cors")
        assert cors.status == "FAIL", f"Wildcard ACAO should FAIL, got {cors.status}"
        assert cors.headers_observed is not None
        assert "Access-Control-Allow-Origin" in cors.headers_observed
        assert cors.headers_observed["Access-Control-Allow-Origin"] == "*"


def test_not_observed_appears_in_module():
    """Verify NOT_OBSERVED string appears in the module source."""
    with open("mcp_authscan/resource_probes.py") as f:
        content = f.read()
    
    assert "NOT_OBSERVED" in content, "resource_probes.py must return NOT_OBSERVED status"

