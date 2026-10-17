import json
from dataclasses import dataclass
from enum import Enum
from typing import List
from urllib.parse import urlparse

import requests

from .cors import probe_cors_requests


class ScanError(Exception):
    """Raised when the scanner cannot perform a meaningful scan."""


def _looks_like_web_page(resp):
    """True if the response is a human-facing web page rather than an MCP/API
    endpoint.

    The false positive this guards against is an SPA dev server or docs site
    that serves an HTML app shell with 200 for every path. Such a page must not
    be read as a zero-auth MCP endpoint. An empty or JSON/SSE 200, by contrast,
    is still treated as a zero-auth signal on an MCP path.
    """
    if "text/html" in resp.headers.get("Content-Type", "").lower():
        return True
    body = (resp.text or "")[:512].lstrip().lower()
    return body.startswith(("<!doctype html", "<html"))


def _parse_initialize_result(resp):
    """Return an MCP `initialize` result dict if the response is a valid
    initialize reply, else None. Handles plain JSON and SSE-framed JSON.
    """
    if resp.status_code != 200:
        return None
    text = (resp.text or "")[:16384]
    candidates = [text]
    if "text/event-stream" in resp.headers.get("Content-Type", "").lower():
        candidates += [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        result = data.get("result") if isinstance(data, dict) else None
        if isinstance(result, dict) and (
            "protocolVersion" in result or "serverInfo" in result or "capabilities" in result
        ):
            return result
    return None

class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Check:
    name: str
    description: str
    endpoint: str
    method: str
    risk_level: RiskLevel
    passed: bool
    details: str
    remediation: str

class MCPScanner:
    def __init__(self, target_url: str, timeout: int = 5, headers=None, checks: str = "default"):
        self.target_url = target_url.rstrip('/')
        self.checks_profile = checks
        parsed_url = urlparse(self.target_url)
        if parsed_url.scheme not in {"http", "https"} or not parsed_url.hostname:
            raise ValueError("Target must be an absolute HTTP or HTTPS URL.")
        if parsed_url.username or parsed_url.password:
            raise ValueError("Target URL must not contain embedded credentials.")
        if timeout < 1:
            raise ValueError("Timeout must be at least one second.")
        self.timeout = timeout
        self.checks: List[Check] = []
        self.session = requests.Session()
        # Identifying headers (e.g. a bug-bounty program's required research
        # header) are applied to the session so every probe -- including the
        # CORS probe, which reuses this session -- carries them.
        if headers:
            self.session.headers.update(headers)

    def scan(self) -> List[Check]:
        self.checks = []
        if not self._check_endpoint_reachability():
            raise ScanError(f"Unable to reach any MCP endpoint at {self.target_url}.")
        self._check_mcp_handshake()
        self._check_sse_auth()
        self._check_message_auth()
        self._check_mcp_endpoint_auth()
        self._check_cors()
        self._check_auth_validation()
        if self.checks_profile == "all":
            self._check_rce_preconditions()
        return self.checks

    def _check_mcp_handshake(self):
        # Non-gating INFO check: confirm the target actually speaks MCP via an
        # `initialize` handshake, and surface its serverInfo/protocol. This adds
        # context for interpreting the other findings; it never flips pass/fail.
        payload = {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "mcp-authscan", "version": "1.0"}},
        }
        for endpoint in ("/mcp", "/message"):
            try:
                resp = self.session.post(
                    f"{self.target_url}{endpoint}", json=payload, timeout=self.timeout,
                    headers={"Accept": "application/json, text/event-stream"})
            except requests.RequestException:
                continue
            result = _parse_initialize_result(resp)
            if result is not None:
                server = result.get("serverInfo") or {}
                details = (f"Confirmed MCP server: {server.get('name', 'unknown')} "
                           f"{server.get('version', '?')} "
                           f"(protocol {result.get('protocolVersion', '?')})")
                self.checks.append(Check(
                    name="MCP Protocol Handshake",
                    description="Confirms the target speaks MCP via an initialize handshake",
                    endpoint=endpoint, method="POST", risk_level=RiskLevel.INFO,
                    passed=True, details=details, remediation="N/A"))
                return True
        self.checks.append(Check(
            name="MCP Protocol Handshake",
            description="Confirms the target speaks MCP via an initialize handshake",
            endpoint="/mcp", method="POST", risk_level=RiskLevel.INFO, passed=True,
            details="MCP initialize handshake not confirmed (target may not be an MCP "
                    "server, or the endpoint requires authentication)",
            remediation="Confirm the endpoint speaks MCP before interpreting other findings"))
        return False

    def _check_rce_preconditions(self):
        # Opt-in RCE-precondition checks (unauth config endpoint, DNS rebinding).
        # Imported lazily to avoid a circular import with rce_checks.
        from .rce_checks import check_dns_rebinding, check_unauth_mcp_config
        self.checks.append(check_unauth_mcp_config(self.target_url, self.timeout, self.session))
        self.checks.append(check_dns_rebinding(self.target_url, self.timeout, self.session))

    def _check_endpoint_reachability(self):
        endpoints = ['/sse', '/message', '/mcp', '/tools/list']
        reachable = False
        details = ""
        for endpoint in endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                resp = self.session.head(url, timeout=self.timeout, allow_redirects=True)
                if resp.status_code < 500:
                    reachable = True
                    details += f"✓ {endpoint} (HTTP {resp.status_code})\n"
                else:
                    details += f"✗ {endpoint} (HTTP {resp.status_code})\n"
            except Exception:
                details += f"✗ {endpoint} (unreachable)\n"
        self.checks.append(Check(name="Endpoint Reachability", description="Checks if MCP endpoints respond", endpoint="*", method="HEAD/GET", risk_level=RiskLevel.INFO, passed=reachable, details=details.strip(), remediation="Ensure endpoints are only accessible from trusted networks"))
        return reachable

    def _check_sse_auth(self):
        try:
            url = f"{self.target_url}/sse"
            resp = self.session.get(url, timeout=self.timeout, headers={"Accept": "text/event-stream"}, stream=True)
            # Content-type only: a real SSE stream never ends, so never read its body.
            web_page = "text/html" in resp.headers.get("Content-Type", "").lower()
            resp.close()
            # A zero-auth 200 is a finding unless it is a human-facing web page
            # (an SPA/docs catch-all serving HTML is not an MCP endpoint).
            unauth = resp.status_code == 200 and not web_page
            passed = not unauth
            details = f"Status: {resp.status_code}"
            if resp.status_code == 200 and web_page:
                details += " (HTML web page, not an MCP endpoint)"
            self.checks.append(Check(name="SSE Endpoint Authentication", description="Checks if /sse requires auth", endpoint="/sse", method="GET", risk_level=RiskLevel.CRITICAL if not passed else RiskLevel.INFO, passed=passed, details=details, remediation="Add authentication middleware to SSE endpoint"))
        except Exception:
            self.checks.append(Check(name="SSE Endpoint Authentication", description="Checks if /sse requires auth", endpoint="/sse", method="GET", risk_level=RiskLevel.INFO, passed=True, details="Endpoint unavailable", remediation="N/A"))

    def _check_message_auth(self):
        try:
            url = f"{self.target_url}/message"
            payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            # A 200 only counts if the server actually answered as JSON-RPC/MCP.
            unauth = resp.status_code == 200 and not _looks_like_web_page(resp)
            passed = not unauth
            details = f"Status: {resp.status_code}"
            if resp.status_code == 200 and not unauth:
                details += " (HTML web page, not an MCP endpoint)"
            self.checks.append(Check(name="Message Endpoint Authentication", description="Checks if /message requires auth", endpoint="/message", method="POST", risk_level=RiskLevel.CRITICAL if not passed else RiskLevel.INFO, passed=passed, details=details, remediation="Add authentication to message endpoint"))
        except Exception:
            self.checks.append(Check(name="Message Endpoint Authentication", description="Checks if /message requires auth", endpoint="/message", method="POST", risk_level=RiskLevel.INFO, passed=True, details="Endpoint unavailable", remediation="N/A"))

    def _check_mcp_endpoint_auth(self):
        try:
            url = f"{self.target_url}/mcp"
            payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            unauth = resp.status_code == 200 and not _looks_like_web_page(resp)
            passed = not unauth
            details = f"Status: {resp.status_code}"
            if resp.status_code == 200 and not unauth:
                details += " (HTML web page, not an MCP endpoint)"
            self.checks.append(Check(name="MCP Endpoint Authentication", description="Checks if /mcp requires auth", endpoint="/mcp", method="POST", risk_level=RiskLevel.CRITICAL if not passed else RiskLevel.INFO, passed=passed, details=details, remediation="Add authentication to MCP endpoint"))
        except Exception:
            self.checks.append(Check(name="MCP Endpoint Authentication", description="Checks if /mcp requires auth", endpoint="/mcp", method="POST", risk_level=RiskLevel.INFO, passed=True, details="Endpoint unavailable", remediation="N/A"))

    def _check_cors(self):
        for endpoint, method in (
            ("/sse", "GET"), ("/message", "POST"), ("/mcp", "POST"), ("/tools/list", "GET")
        ):
            try:
                assessment = probe_cors_requests(
                    f"{self.target_url}{endpoint}", method, self.timeout, self.session
                )
                self.checks.append(Check(
                    name="CORS Configuration", description=assessment.summary,
                    endpoint=endpoint, method=method,
                    risk_level=RiskLevel(assessment.severity), passed=not assessment.is_finding,
                    details=assessment.details, remediation=assessment.remediation,
                ))
            except requests.RequestException:
                self.checks.append(Check(
                    name="CORS Configuration", description="CORS assessment incomplete",
                    endpoint=endpoint, method=method, risk_level=RiskLevel.INFO, passed=True,
                    details="Request failed; CORS safety could not be established.",
                    remediation="Retry the endpoint or review its data and authentication context.",
                ))

    def _check_auth_validation(self):
        try:
            url = f"{self.target_url}/message"
            payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            resp = self.session.post(url, json=payload, timeout=self.timeout, headers={"Authorization": "Bearer fake-token-12345"})
            # The fake token is only "accepted" if the server actually served an
            # MCP/JSON-RPC response to it, not merely returned some 200 page.
            accepted = resp.status_code == 200 and not _looks_like_web_page(resp)
            passed = not accepted
            details = f"Fake token status: {resp.status_code}"
            if resp.status_code == 200 and not accepted:
                details += " (not a JSON-RPC/MCP response)"
            self.checks.append(Check(name="Authorization Header Validation", description="Checks if fake tokens rejected", endpoint="/message", method="POST", risk_level=RiskLevel.HIGH if not passed else RiskLevel.INFO, passed=passed, details=details, remediation="Validate auth token values"))
        except Exception:
            self.checks.append(Check(name="Authorization Header Validation", description="Checks if fake tokens rejected", endpoint="/message", method="POST", risk_level=RiskLevel.INFO, passed=True, details="Could not test", remediation="N/A"))
