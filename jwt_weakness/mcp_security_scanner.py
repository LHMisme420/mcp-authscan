"""
VATA MCP Security Scanner - Comprehensive Vulnerability Detection
The King of MCP Detection™
"""
import requests
import json
from typing import List, Dict

class MCPSecurityScanner:
    """Detect all major MCP security vulnerabilities."""
    
    def __init__(self, url: str, timeout: int = 3):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.findings = []
    
    def check_metadata_disclosure(self) -> List[Dict]:
        """RFC 9728 metadata exposure."""
        findings = []
        try:
            r = requests.get(f"{self.url}/.well-known/mcp.json", timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "MCP_METADATA_EXPOSED",
                    "severity": "MEDIUM",
                    "endpoint": "/.well-known/mcp.json"
                })
        except:
            pass
        return findings
    
    def check_tool_access_control(self) -> List[Dict]:
        """Can tools be called without authentication?"""
        findings = []
        try:
            r = requests.post(f"{self.url}/api/tools/call", 
                            json={"tool": "test", "args": {}},
                            timeout=self.timeout)
            if r.status_code in (200, 400):  # 400 = tool exists, 200 = executed
                findings.append({
                    "type": "UNAUTHENTICATED_TOOL_CALL",
                    "severity": "CRITICAL",
                    "message": "Tools callable without authentication"
                })
        except:
            pass
        return findings
    
    def check_unsafe_deserialization(self) -> List[Dict]:
        """JSON-RPC parameter handling."""
        findings = []
        try:
            # Test pickle/yaml injection
            payloads = [
                '{"__proto__": {"isAdmin": true}}',
                '{"constructor": {"prototype": {"isAdmin": true}}}',
                '${7*7}',  # Template injection
                '../../../etc/passwd'  # Path traversal
            ]
            
            for payload in payloads:
                try:
                    r = requests.post(f"{self.url}/api/call",
                                    json={"param": payload},
                                    timeout=self.timeout)
                    if "root:" in r.text or "admin" in r.text:
                        findings.append({
                            "type": "UNSAFE_DESERIALIZATION",
                            "severity": "CRITICAL",
                            "payload": payload[:30]
                        })
                        break
                except:
                    pass
        except:
            pass
        return findings
    
    def check_tool_injection(self) -> List[Dict]:
        """Command/parameter injection in tools."""
        findings = []
        try:
            payloads = [
                {"input": "test; whoami"},
                {"input": "test$(whoami)"},
                {"input": "test`whoami`"},
                {"input": "test | cat /etc/passwd"}
            ]
            
            for payload in payloads:
                try:
                    r = requests.post(f"{self.url}/api/tools/execute",
                                    json=payload,
                                    timeout=self.timeout)
                    if r.status_code == 200:
                        findings.append({
                            "type": "TOOL_INJECTION_POSSIBLE",
                            "severity": "CRITICAL",
                            "payload_type": list(payload.keys())[0]
                        })
                        break
                except:
                    pass
        except:
            pass
        return findings
    
    def check_resource_traversal(self) -> List[Dict]:
        """Directory/file traversal in resource access."""
        findings = []
        try:
            traversal_paths = [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc%2fpasswd",
                "/etc/passwd"
            ]
            
            for path in traversal_paths:
                try:
                    r = requests.get(f"{self.url}/api/resources/{path}",
                                   timeout=self.timeout)
                    if r.status_code == 200 and "root:" in r.text:
                        findings.append({
                            "type": "PATH_TRAVERSAL",
                            "severity": "CRITICAL",
                            "path": path
                        })
                        break
                except:
                    pass
        except:
            pass
        return findings
    
    def check_deprecated_versions(self) -> List[Dict]:
        """Old/vulnerable MCP protocol versions."""
        findings = []
        try:
            r = requests.get(f"{self.url}/api/version", timeout=self.timeout)
            if r.status_code == 200:
                version = r.json().get("version", "unknown")
                # Check for old versions
                if version.startswith("1.") or version.startswith("0."):
                    findings.append({
                        "type": "DEPRECATED_MCP_VERSION",
                        "severity": "MEDIUM",
                        "version": version
                    })
        except:
            pass
        return findings
    
    def check_capability_bypass(self) -> List[Dict]:
        """Declared vs actual capabilities mismatch."""
        findings = []
        try:
            # Get declared capabilities
            r = requests.get(f"{self.url}/.well-known/mcp.json", timeout=self.timeout)
            if r.status_code == 200:
                meta = r.json()
                capabilities = meta.get("capabilities", {})
                
                # Test undeclared capabilities
                if not capabilities.get("tools"):
                    r = requests.get(f"{self.url}/api/tools", timeout=self.timeout)
                    if r.status_code == 200:
                        findings.append({
                            "type": "CAPABILITY_BYPASS",
                            "severity": "MEDIUM",
                            "message": "Tools accessible despite not being declared"
                        })
        except:
            pass
        return findings
    
    def check_server_config_exposure(self) -> List[Dict]:
        """Secrets in server configuration."""
        findings = []
        try:
            config_files = [
                "/config.json", "/settings.json", "/.env",
                "/mcp.json", "/server.json", "/config.yaml"
            ]
            
            for cf in config_files:
                try:
                    r = requests.get(f"{self.url}{cf}", timeout=self.timeout)
                    if r.status_code == 200:
                        if any(secret in r.text.lower() for secret in 
                               ["secret", "password", "token", "key", "api_key"]):
                            findings.append({
                                "type": "CONFIG_SECRETS_EXPOSED",
                                "severity": "CRITICAL",
                                "file": cf
                            })
                except:
                    pass
        except:
            pass
        return findings
    
    def check_mcp_proxy_bypass(self) -> List[Dict]:
        """Zero-auth MCP proxy vulnerabilities."""
        findings = []
        try:
            # Test proxy access
            r = requests.get(f"{self.url}/proxy/", timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "MCP_PROXY_ZERO_AUTH",
                    "severity": "CRITICAL",
                    "message": "MCP proxy accessible without authentication"
                })
        except:
            pass
        return findings
    
    def check_tool_amplification(self) -> List[Dict]:
        """Tool chaining for DoS."""
        findings = []
        try:
            # Detect if tools can call other tools
            r = requests.post(f"{self.url}/api/tools/call",
                            json={"tool": "shell", "args": {"cmd": "echo test"}},
                            timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "TOOL_AMPLIFICATION_POSSIBLE",
                    "severity": "HIGH",
                    "message": "Shell/execution tools accessible for chaining"
                })
        except:
            pass
        return findings
    
    def run(self) -> List[Dict]:
        """Run all MCP security checks."""
        all_findings = []
        all_findings.extend(self.check_metadata_disclosure())
        all_findings.extend(self.check_tool_access_control())
        all_findings.extend(self.check_unsafe_deserialization())
        all_findings.extend(self.check_tool_injection())
        all_findings.extend(self.check_resource_traversal())
        all_findings.extend(self.check_deprecated_versions())
        all_findings.extend(self.check_capability_bypass())
        all_findings.extend(self.check_server_config_exposure())
        all_findings.extend(self.check_mcp_proxy_bypass())
        all_findings.extend(self.check_tool_amplification())
        return all_findings
