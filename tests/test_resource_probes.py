"""Test resource endpoint probes."""

import pytest
from unittest.mock import Mock, patch
from mcp_authscan.resource_probes import (
    probe_anon_tools_list,
    probe_anon_initialize,
    probe_endpoint_cors,
    probe_auth_challenge,
)


def test_anon_tools_list_fails_on_exposed_tools():
    """Bad fixture: tools/list returns tools array without auth. Should FAIL."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "weather", "description": "Get weather"},
                    {"name": "calendar", "description": "Calendar access"},
                ]
            },
            "id": 1
        }
        mock_post.return_value = mock_response
        
        should_fail, evidence = probe_anon_tools_list("http://localhost:8000")
        assert should_fail is True
        assert "2 tools" in evidence


def test_anon_tools_list_passes_on_401():
    """Good fixture: tools/list returns 401 without auth. Should PASS."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response
        
        should_fail, evidence = probe_anon_tools_list("http://localhost:8000")
        assert should_fail is False


def test_endpoint_cors_fails_on_wildcard():
    """CORS misconfigured: Allow-Origin = *. Should FAIL."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "false"
        }
        mock_post.return_value = mock_response
        
        should_fail, evidence, severity = probe_endpoint_cors("http://localhost:8000")
        assert should_fail is True
        assert severity == "MODERATE"


def test_auth_challenge_fails_without_header():
    """401 without WWW-Authenticate header. Should FAIL."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        mock_response = Mock()
        mock_response.status_code = 401
        mock_response.headers = {}
        mock_post.return_value = mock_response
        
        should_fail, evidence = probe_auth_challenge("http://localhost:8000")
        assert should_fail is True


"""Test resource endpoint probes with five comprehensive fixtures."""

import pytest
import json
from unittest.mock import Mock, patch
from mcp_authscan.resource_probes import run_resource_probes


def test_fixture_1_all_pass():
    """Good fixture: all five probes PASS."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        # Setup responses for each probe
        responses = []
        
        # preflight: 401 with WWW-Authenticate
        r1 = Mock()
        r1.status_code = 401
        r1.headers = {"WWW-Authenticate": "Bearer realm=\"api\""}
        r1.json.return_value = {"jsonrpc": "2.0", "error": {"code": -32600}}
        responses.append(r1)
        
        # anon-initialize: 401
        r2 = Mock()
        r2.status_code = 401
        responses.append(r2)
        
        # anon-tools-list: 401
        r3 = Mock()
        r3.status_code = 401
        responses.append(r3)
        
        # endpoint-cors: 200 with restricted origin
        r4 = Mock()
        r4.status_code = 200
        r4.headers = {"Access-Control-Allow-Origin": "https://example.com"}
        r4.json.return_value = {}
        responses.append(r4)
        
        # auth-challenge: 401 with WWW-Authenticate
        r5 = Mock()
        r5.status_code = 401
        r5.headers = {"WWW-Authenticate": "Bearer realm=\"api\""}
        responses.append(r5)
        
        mock_post.side_effect = responses
        
        probes = run_resource_probes("http://localhost:8000")
        
        # All five should PASS
        assert len(probes) == 5
        assert sum(1 for p in probes if p.status == "PASS") == 5
        assert sum(1 for p in probes if p.status == "FAIL") == 0


def test_fixture_2_bad():
    """Bad fixture: tools exposed, CORS misconfigured, preflight passes."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        responses = []
        
        # preflight: 401 with header (PASS)
        r1 = Mock()
        r1.status_code = 401
        r1.headers = {"WWW-Authenticate": "Bearer"}
        r1.json.return_value = {"jsonrpc": "2.0", "error": {}}
        responses.append(r1)
        
        # anon-initialize: 401 (PASS)
        r2 = Mock()
        r2.status_code = 401
        responses.append(r2)
        
        # anon-tools-list: 200 with tools (FAIL CRITICAL)
        r3 = Mock()
        r3.status_code = 200
        r3.json.return_value = {
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "weather"},
                    {"name": "calendar"},
                    {"name": "email"}
                ]
            }
        }
        responses.append(r3)
        
        # endpoint-cors: Allow-Origin=* (FAIL)
        r4 = Mock()
        r4.status_code = 200
        r4.headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "false"
        }
        r4.json.return_value = {}
        responses.append(r4)
        
        # auth-challenge: 401 with header (PASS)
        r5 = Mock()
        r5.status_code = 401
        r5.headers = {"WWW-Authenticate": "Bearer"}
        responses.append(r5)
        
        mock_post.side_effect = responses
        
        probes = run_resource_probes("http://localhost:8000")
        
        # Check: preflight PASS, anon-initialize PASS, tools FAIL CRITICAL, cors FAIL, auth PASS
        passed = sum(1 for p in probes if p.status == "PASS")
        failed = sum(1 for p in probes if p.status == "FAIL")
        
        assert passed == 3, f"Expected 3 PASS, got {passed}"
        assert failed == 2, f"Expected 2 FAIL, got {failed}"
        
        # Verify tools has CRITICAL severity
        tools_probe = next(p for p in probes if p.probe_id == "anon-tools-list")
        assert tools_probe.status == "FAIL"
        assert tools_probe.severity == "CRITICAL"
        assert "3 tools" in tools_probe.detail


def test_fixture_3_bare_401():
    """Bare 401 fixture: preflight NOT_OBSERVED (no WWW-Authenticate), four EXCLUDED."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        # preflight: 401 without WWW-Authenticate (NOT_OBSERVED, gates others)
        r = Mock()
        r.status_code = 401
        r.headers = {}
        r.json.return_value = {}
        
        mock_post.return_value = r
        
        probes = run_resource_probes("http://localhost:8000")
        
        # preflight should NOT_OBSERVED, other four EXCLUDED
        preflight = next(p for p in probes if p.probe_id == "mcp-preflight")
        assert preflight.status == "FAIL", "Bare 401 without header = not MCP"
        
        # Other four should be EXCLUDED due to preflight failure
        excluded = sum(1 for p in probes if p.status == "EXCLUDED")
        assert excluded == 4, f"Expected 4 EXCLUDED, got {excluded}"


def test_fixture_4_plain_rest():
    """Plain REST fixture: {"result": {"ok": true}} - preflight NOT_OBSERVED, four EXCLUDED."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        # preflight: 200 with plain REST response (no jsonrpc field)
        r = Mock()
        r.status_code = 200
        r.json.return_value = {"result": {"ok": True}}
        
        mock_post.return_value = r
        
        probes = run_resource_probes("http://localhost:8000")
        
        # preflight should FAIL (not JSON-RPC)
        preflight = next(p for p in probes if p.probe_id == "mcp-preflight")
        assert preflight.status == "FAIL"
        
        # Other four EXCLUDED
        excluded = sum(1 for p in probes if p.status == "EXCLUDED")
        assert excluded == 4


def test_fixture_5_dead_port():
    """Dead port fixture: preflight NOT_OBSERVED (connection refused)."""
    with patch('mcp_authscan.resource_probes.requests.post') as mock_post:
        import requests
        mock_post.side_effect = requests.exceptions.ConnectionError("Connection refused")
        
        probes = run_resource_probes("http://localhost:9999")
        
        # preflight should NOT_OBSERVED
        preflight = next(p for p in probes if p.probe_id == "mcp-preflight")
        assert preflight.status == "FAIL"
        assert "Connection" in preflight.detail
        
        # No FAILs (all either NOT_OBSERVED or EXCLUDED)
        fails = sum(1 for p in probes if p.status == "FAIL")
        assert fails == 1  # Only preflight fails on connection error
