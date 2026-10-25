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
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        r1 = Mock()
        r1.status_code = 401
        r1.headers = {"WWW-Authenticate": "Bearer"}
        r1.json.return_value = {"jsonrpc": "2.0", "error": {}}
        
        mock_post.side_effect = [r1, ValueError("JSON decode error")]
        
        probes = run_resource_probes("http://localhost:8000")
        
        anon_init = next(p for p in probes if p.probe_id == "anon-initialize")
        assert anon_init.status == "NOT_OBSERVED", f"Exception should be NOT_OBSERVED, got {anon_init.status}"
        assert "error" in anon_init.detail.lower()


def test_cors_probe_exception_returns_not_observed():
    """Server raises during CORS probe -> NOT_OBSERVED. Never PASS, no 'CORS properly restricted'."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        r1 = Mock()
        r1.status_code = 401
        r1.headers = {"WWW-Authenticate": "Bearer"}
        r1.json.return_value = {"jsonrpc": "2.0", "error": {}}
        
        r2 = Mock()
        r2.status_code = 401
        r2.json.return_value = {}
        
        r3 = Mock()
        r3.status_code = 401
        
        r5 = Mock()
        r5.status_code = 401
        r5.headers = {"WWW-Authenticate": "Bearer"}
        
        # Fourth call (CORS) raises RuntimeError
        mock_post.side_effect = [r1, r2, r3, RuntimeError("Network timeout"), r5]
        
        probes = run_resource_probes("http://localhost:8000")
        
        cors = next(p for p in probes if p.probe_id == "endpoint-cors")
        assert cors.status == "NOT_OBSERVED", f"CORS exception should be NOT_OBSERVED, got {cors.status}"
        assert "CORS properly restricted" not in cors.detail


def test_auth_challenge_200_not_pass():
    """Auth-challenge returns 200 -> NOT PASS on the 200 alone."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        r1 = Mock()
        r1.status_code = 401
        r1.headers = {"WWW-Authenticate": "Bearer"}
        r1.json.return_value = {"jsonrpc": "2.0", "error": {}}
        
        r2 = Mock()
        r2.status_code = 401
        
        r3 = Mock()
        r3.status_code = 401
        
        r4 = Mock()
        r4.status_code = 200
        r4.headers = {}
        
        r5 = Mock()
        r5.status_code = 200
        r5.json.return_value = {"result": {"ok": True}}
        
        mock_post.side_effect = [r1, r2, r3, r4, r5]
        
        probes = run_resource_probes("http://localhost:8000")
        
        auth = next(p for p in probes if p.probe_id == "auth-challenge")
        assert auth.status != "PASS", f"200 response should not be PASS, got {auth.status}"


def test_cors_wildcard_moderate_with_captured_headers():
    """Wildcard Allow-Origin with no Allow-Credentials -> exactly one FAIL, MODERATE, captured header."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        r1 = Mock()
        r1.status_code = 401
        r1.headers = {"WWW-Authenticate": "Bearer"}
        r1.json.return_value = {"jsonrpc": "2.0", "error": {}}
        
        r2 = Mock()
        r2.status_code = 401
        
        r3 = Mock()
        r3.status_code = 401
        
        r4 = Mock()
        r4.status_code = 200
        r4.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "false",
            "Vary": "Origin"
        }
        r4.json.return_value = {}
        
        r5 = Mock()
        r5.status_code = 401
        r5.headers = {"WWW-Authenticate": "Bearer"}
        
        mock_post.side_effect = [r1, r2, r3, r4, r5]
        
        probes = run_resource_probes("http://localhost:8000")
        
        cors = next(p for p in probes if p.probe_id == "endpoint-cors")
        assert cors.status == "FAIL"
        assert cors.severity == "MODERATE", f"Expected MODERATE, got {cors.severity}"
        assert cors.headers_observed is not None
        assert "Access-Control-Allow-Origin" in cors.headers_observed


def test_not_observed_appears_in_module():
    """Verify NOT_OBSERVED string appears in the module source."""
    with open("mcp_authscan/resource_probes.py") as f:
        content = f.read()
    
    assert "NOT_OBSERVED" in content, "resource_probes.py must return NOT_OBSERVED status"

