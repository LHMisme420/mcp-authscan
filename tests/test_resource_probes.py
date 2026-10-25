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
