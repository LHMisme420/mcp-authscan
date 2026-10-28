"""Test resource probes with four-branch verdict logic.

Tests verify:
- 5xx → NOT_OBSERVED
- Correct behavior → PASS
- Vulnerability → FAIL
- Non-assessable → NOT_OBSERVED
- No MODERATE or MEDIUM severity strings
"""

import pytest
from unittest.mock import patch
from mcp_authscan.resource_probes import (
    probe_mcp_preflight,
    probe_anon_initialize,
    probe_anon_tools_list,
    probe_endpoint_cors,
    probe_auth_challenge,
)


class TestMcpPreflight:
    """Test probe_mcp_preflight four-branch logic."""

    def test_5xx_returns_not_observed(self):
        """5xx error should return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (500, {}, b"")
            result = probe_mcp_preflight("http://example.com")
            assert result.status == "NOT_OBSERVED"
            assert result.http_status == 500

    def test_401_with_www_authenticate_returns_pass(self):
        """401 with WWW-Authenticate header is correct behavior, return PASS."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                401,
                {"WWW-Authenticate": "Bearer realm=\"example\""},
                b"Unauthorized"
            )
            result = probe_mcp_preflight("http://example.com")
            assert result.status == "PASS"
            assert result.http_status == 401

    def test_401_without_www_authenticate_returns_fail(self):
        """401 without WWW-Authenticate header is vulnerability, return FAIL."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (401, {}, b"Unauthorized")
            result = probe_mcp_preflight("http://example.com")
            assert result.status == "FAIL"

    def test_200_non_json_returns_not_observed(self):
        """200 but body is not JSON-RPC, return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (200, {}, b"<html>Not JSON-RPC</html>")
            result = probe_mcp_preflight("http://example.com")
            assert result.status == "NOT_OBSERVED"


class TestAnonInitialize:
    """Test probe_anon_initialize four-branch logic."""

    def test_5xx_returns_not_observed(self):
        """5xx error should return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (503, {}, b"Service Unavailable")
            result = probe_anon_initialize("http://example.com")
            assert result.status == "NOT_OBSERVED"

    def test_401_correct_behavior_returns_pass(self):
        """401 response without exposed serverInfo is correct, return PASS."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                401,
                {},
                b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Authentication required"}}'
            )
            result = probe_anon_initialize("http://example.com")
            assert result.status == "PASS"

    def test_vulnerability_exposes_serverinfo_returns_fail(self):
        """Response with serverInfo/capabilities exposed is vulnerability, return FAIL."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {},
                b'{"jsonrpc":"2.0","result":{"capabilities":{"roots":{"listChanged":true}},"serverInfo":{"name":"example"}}}'
            )
            result = probe_anon_initialize("http://example.com")
            assert result.status == "FAIL"

    def test_non_json_response_returns_not_observed(self):
        """Non-JSON response, cannot assess, return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (200, {}, b"Plain text response")
            result = probe_anon_initialize("http://example.com")
            assert result.status == "NOT_OBSERVED"


class TestAnonToolsList:
    """Test probe_anon_tools_list four-branch logic."""

    def test_5xx_returns_not_observed(self):
        """5xx error should return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (502, {}, b"Bad Gateway")
            result = probe_anon_tools_list("http://example.com")
            assert result.status == "NOT_OBSERVED"

    def test_401_correct_behavior_returns_pass(self):
        """401 response is correct behavior, return PASS."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                401,
                {},
                b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unauthorized"}}'
            )
            result = probe_anon_tools_list("http://example.com")
            assert result.status == "PASS"

    def test_vulnerability_returns_tools_returns_fail(self):
        """Response with non-empty tools array is vulnerability, return FAIL."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {},
                b'{"jsonrpc":"2.0","result":{"tools":[{"name":"tool1"}]}}'
            )
            result = probe_anon_tools_list("http://example.com")
            assert result.status == "FAIL"

    def test_200_with_empty_tools_returns_not_observed(self):
        """200 with empty tools array is unusual, not standard MCP response, return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {},
                b'{"jsonrpc":"2.0","result":{"tools":[]}}'
            )
            result = probe_anon_tools_list("http://example.com")
            assert result.status == "NOT_OBSERVED"

    def test_200_with_error_response_returns_pass(self):
        """200 with error response is correct behavior, return PASS."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {},
                b'{"jsonrpc":"2.0","error":{"code":-32600,"message":"Unauthorized"}}'
            )
            result = probe_anon_tools_list("http://example.com")
            assert result.status == "PASS"


class TestEndpointCors:
    """Test probe_endpoint_cors four-branch logic."""

    def test_5xx_returns_not_observed(self):
        """5xx error should return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (500, {}, b"Server Error")
            result = probe_endpoint_cors("http://example.com")
            assert result.status == "NOT_OBSERVED"

    def test_absent_acao_returns_not_observed(self):
        """Absent Access-Control-Allow-Origin header, return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (200, {}, b'{"jsonrpc":"2.0","result":{}}')
            result = probe_endpoint_cors("http://example.com")
            assert result.status == "NOT_OBSERVED"
            assert "not configured for CORS" in result.detail

    def test_wildcard_acao_returns_fail(self):
        """Wildcard Access-Control-Allow-Origin is vulnerability, return FAIL."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {"Access-Control-Allow-Origin": "*"},
                b'{"jsonrpc":"2.0","result":{}}'
            )
            result = probe_endpoint_cors("http://example.com")
            assert result.status == "FAIL"
            assert "Allow-Origin=*" in result.detail

    def test_echo_origin_returns_fail(self):
        """Echo back request Origin is vulnerability, return FAIL."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {"Access-Control-Allow-Origin": "https://boardy.invalid"},
                b'{"jsonrpc":"2.0","result":{}}'
            )
            result = probe_endpoint_cors("http://example.com")
            assert result.status == "FAIL"
            assert "CORS misconfigured" in result.detail
            assert result.severity == "HIGH"  # No credentials, so HIGH

    def test_specific_origin_returns_pass(self):
        """Specific restricted origin is correct behavior, return PASS."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                200,
                {"Access-Control-Allow-Origin": "https://trusted-origin.com"},
                b'{"jsonrpc":"2.0","result":{}}'
            )
            result = probe_endpoint_cors("http://example.com")
            assert result.status == "PASS"
            assert "properly restricted" in result.detail


class TestAuthChallenge:
    """Test probe_auth_challenge four-branch logic."""

    def test_5xx_returns_not_observed(self):
        """5xx error should return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (500, {}, b"Server Error")
            result = probe_auth_challenge("http://example.com")
            assert result.status == "NOT_OBSERVED"

    def test_401_with_www_authenticate_returns_pass(self):
        """401 with WWW-Authenticate header is correct behavior, return PASS."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (
                401,
                {"WWW-Authenticate": "Bearer realm=\"example\""},
                b"Unauthorized"
            )
            result = probe_auth_challenge("http://example.com")
            assert result.status == "PASS"
            assert "WWW-Authenticate" in result.headers_observed

    def test_401_without_www_authenticate_returns_fail(self):
        """401 without WWW-Authenticate header is vulnerability, return FAIL."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (401, {}, b"Unauthorized")
            result = probe_auth_challenge("http://example.com")
            assert result.status == "FAIL"
            assert "absent" in result.headers_observed.get("WWW-Authenticate", "").lower()

    def test_non_401_returns_not_observed(self):
        """Non-401 response, cannot assess auth challenge, return NOT_OBSERVED."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (200, {}, b'{"jsonrpc":"2.0","result":{}}')
            result = probe_auth_challenge("http://example.com")
            assert result.status == "NOT_OBSERVED"
            assert "Expected 401 challenge" in result.detail


class TestNoSeverityStrings:
    """Verify MODERATE and MEDIUM severity strings are removed."""

    def test_no_moderate_severity_in_any_probe(self):
        """No resource probe should return MODERATE severity."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (200, {}, b"test")

            probes = [
                probe_mcp_preflight,
                probe_anon_initialize,
                probe_anon_tools_list,
                probe_endpoint_cors,
                probe_auth_challenge,
            ]

            for probe in probes:
                result = probe("http://example.com")
                assert result.severity != "MODERATE", f"{probe.__name__} returned MODERATE"

    def test_no_medium_severity_in_any_probe(self):
        """No resource probe should return MEDIUM severity."""
        with patch("mcp_authscan.resource_probes._egress_guard_fetch") as mock_fetch:
            mock_fetch.return_value = (200, {}, b"test")

            probes = [
                probe_mcp_preflight,
                probe_anon_initialize,
                probe_anon_tools_list,
                probe_endpoint_cors,
                probe_auth_challenge,
            ]

            for probe in probes:
                result = probe("http://example.com")
                assert result.severity != "MEDIUM", f"{probe.__name__} returned MEDIUM"
