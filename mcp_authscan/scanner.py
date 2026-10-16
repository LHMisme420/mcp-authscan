import requests
import json
from typing import List
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse
from .cors import probe_cors_requests


class ScanError(Exception):
    """Raised when the scanner cannot perform a meaningful scan."""

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
    def __init__(self, target_url: str, timeout: int = 5):
        self.target_url = target_url.rstrip('/')
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
    
    def scan(self) -> List[Check]:
        self.checks = []
        if not self._check_endpoint_reachability():
            raise ScanError(f"Unable to reach any MCP endpoint at {self.target_url}.")
        self._check_sse_auth()
        self._check_message_auth()
        self._check_mcp_endpoint_auth()
        self._check_cors()
        self._check_auth_validation()
        return self.checks
    
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
            except Exception as e:
                details += f"✗ {endpoint} (unreachable)\n"
        self.checks.append(Check(name="Endpoint Reachability", description="Checks if MCP endpoints respond", endpoint="*", method="HEAD/GET", risk_level=RiskLevel.INFO, passed=reachable, details=details.strip(), remediation="Ensure endpoints are only accessible from trusted networks"))
        return reachable
    
    def _check_sse_auth(self):
        try:
            url = f"{self.target_url}/sse"
            resp = self.session.get(url, timeout=self.timeout, headers={"Accept": "text/event-stream"})
            passed = resp.status_code != 200
            self.checks.append(Check(name="SSE Endpoint Authentication", description="Checks if /sse requires auth", endpoint="/sse", method="GET", risk_level=RiskLevel.CRITICAL if not passed else RiskLevel.INFO, passed=passed, details=f"Status: {resp.status_code}", remediation="Add authentication middleware to SSE endpoint"))
        except Exception as e:
            self.checks.append(Check(name="SSE Endpoint Authentication", description="Checks if /sse requires auth", endpoint="/sse", method="GET", risk_level=RiskLevel.INFO, passed=True, details=f"Endpoint unavailable", remediation="N/A"))
    
    def _check_message_auth(self):
        try:
            url = f"{self.target_url}/message"
            payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            passed = resp.status_code != 200
            self.checks.append(Check(name="Message Endpoint Authentication", description="Checks if /message requires auth", endpoint="/message", method="POST", risk_level=RiskLevel.CRITICAL if not passed else RiskLevel.INFO, passed=passed, details=f"Status: {resp.status_code}", remediation="Add authentication to message endpoint"))
        except:
            self.checks.append(Check(name="Message Endpoint Authentication", description="Checks if /message requires auth", endpoint="/message", method="POST", risk_level=RiskLevel.INFO, passed=True, details="Endpoint unavailable", remediation="N/A"))
    
    def _check_mcp_endpoint_auth(self):
        try:
            url = f"{self.target_url}/mcp"
            payload = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            passed = resp.status_code != 200
            self.checks.append(Check(name="MCP Endpoint Authentication", description="Checks if /mcp requires auth", endpoint="/mcp", method="POST", risk_level=RiskLevel.CRITICAL if not passed else RiskLevel.INFO, passed=passed, details=f"Status: {resp.status_code}", remediation="Add authentication to MCP endpoint"))
        except:
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
            passed = resp.status_code != 200
            self.checks.append(Check(name="Authorization Header Validation", description="Checks if fake tokens rejected", endpoint="/message", method="POST", risk_level=RiskLevel.HIGH if not passed else RiskLevel.INFO, passed=passed, details=f"Fake token status: {resp.status_code}", remediation="Validate auth token values"))
        except:
            self.checks.append(Check(name="Authorization Header Validation", description="Checks if fake tokens rejected", endpoint="/message", method="POST", risk_level=RiskLevel.INFO, passed=True, details="Could not test", remediation="N/A"))
