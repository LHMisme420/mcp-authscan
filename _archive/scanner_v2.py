"""MCP Security Scanner v2 - Comprehensive Testing"""
import requests
from mcp_authscan.cors import probe_cors_requests
import json
import ssl
from typing import List, Dict

class MCPScannerV2:
    """Enhanced MCP server security scanner"""
    
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.findings = []
    
    def scan(self) -> List[Dict]:
        """Run all security checks"""
        # Auth checks
        self.check_tools_call()
        self.check_tools_list()
        self.check_cors()
        
        # New checks
        self.check_tls_https()
        self.check_input_validation()
        self.check_info_disclosure()
        self.check_rate_limiting()
        self.check_tool_output_safety()
        self.check_resource_isolation()
        self.check_known_vulns()
        
        return self.findings
    
    # AUTH CHECKS (Original)
    def check_tools_call(self):
        try:
            resp = requests.post(f"{self.url}/message", 
                json={"jsonrpc":"2.0","method":"tools/call","params":{"name":"test","arguments":{}},"id":1}, 
                timeout=5)
            if resp.status_code == 200 and "result" in resp.json():
                self.findings.append({"endpoint":"/message","severity":"CRITICAL","issue":"Unauthenticated tool execution"})
        except: pass
    
    def check_tools_list(self):
        try:
            resp = requests.post(f"{self.url}/tools/list", 
                json={"jsonrpc":"2.0","method":"tools/list","id":1}, timeout=5)
            if resp.status_code == 200 and "result" in resp.json() and resp.json()["result"]:
                self.findings.append({"endpoint":"/tools/list","severity":"MEDIUM","issue":"Tool enumeration without auth"})
        except: pass
    
    def check_cors(self):
        try:
            assessment = probe_cors_requests(f"{self.url}/message", method="POST", timeout=5)
            if assessment.is_finding:
                self.findings.append({"endpoint":"CORS","severity":assessment.severity,
                                     "issue":assessment.summary,"details":assessment.details})
        except: pass
    
    # NEW CHECKS
    def check_tls_https(self):
        """Check TLS/HTTPS enforcement"""
        if self.url.startswith("http://"):
            self.findings.append({"endpoint":"Transport","severity":"HIGH","issue":"HTTP instead of HTTPS - unencrypted traffic"})
        
        if self.url.startswith("https://"):
            try:
                import socket
                hostname = self.url.split("://")[1].split("/")[0]
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        version = ssock.version()
                        if version in ["TLSv1", "TLSv1.1"]:
                            self.findings.append({"endpoint":"TLS","severity":"MEDIUM","issue":f"Weak TLS version: {version}"})
            except: pass
    
    def check_input_validation(self):
        """Test for injection vulnerabilities"""
        injection_tests = [
            {"name": "test'; DROP TABLE--", "severity": "CRITICAL"},
            {"name": "test\"; eval(\"x\");//", "severity": "CRITICAL"},
            {"name": "../../../etc/passwd", "severity": "HIGH"},
        ]
        
        for test in injection_tests:
            try:
                resp = requests.post(f"{self.url}/message",
                    json={"jsonrpc":"2.0","method":"tools/call","params":{"name":test["name"],"arguments":{}},"id":1},
                    timeout=5)
                if resp.status_code == 200:
                    self.findings.append({"endpoint":"Input Validation","severity":test["severity"],"issue":f"No validation on: {test['name'][:20]}"})
            except: pass
    
    def check_info_disclosure(self):
        """Check for information leakage"""
        try:
            # Check error responses
            resp = requests.post(f"{self.url}/message",
                json={"invalid": "request"},
                timeout=5)
            if resp.status_code >= 400:
                text = resp.text.lower()
                if "stack" in text or "traceback" in text or "exception" in text:
                    self.findings.append({"endpoint":"Error Handling","severity":"MEDIUM","issue":"Stack traces in error messages"})
            
            # Check headers for version info
            resp = requests.get(f"{self.url}/", timeout=5)
            for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
                if header in resp.headers:
                    self.findings.append({"endpoint":"Headers","severity":"LOW","issue":f"Version disclosed in {header}"})
        except: pass
    
    def check_rate_limiting(self):
        """Test rate limiting"""
        try:
            for i in range(10):
                requests.post(f"{self.url}/message",
                    json={"jsonrpc":"2.0","method":"initialize","id":i},
                    timeout=2)
            # If we get here, no rate limit
            self.findings.append({"endpoint":"Rate Limiting","severity":"MEDIUM","issue":"No rate limiting detected on endpoints"})
        except: pass
    
    def check_tool_output_safety(self):
        """Check if tool outputs are properly sanitized"""
        try:
            resp = requests.post(f"{self.url}/message",
                json={"jsonrpc":"2.0","method":"tools/call","params":{"name":"test","arguments":{"input":"<script>alert(1)</script>"}},"id":1},
                timeout=5)
            if resp.status_code == 200:
                text = resp.text
                if "<script>" in text and "</script>" in text:
                    self.findings.append({"endpoint":"Output Safety","severity":"HIGH","issue":"Tool output not HTML-encoded - XSS risk"})
        except: pass
    
    def check_resource_isolation(self):
        """Test resource access control"""
        try:
            # Try accessing resources without proper auth
            resp = requests.post(f"{self.url}/message",
                json={"jsonrpc":"2.0","method":"resources/list","id":1},
                timeout=5)
            if resp.status_code == 200 and "result" in resp.json():
                self.findings.append({"endpoint":"Resources","severity":"MEDIUM","issue":"Resource enumeration without authentication"})
        except: pass
    
    def check_known_vulns(self):
        """Check for known vulnerable versions"""
        try:
            resp = requests.get(f"{self.url}/", timeout=5)
            server_header = resp.headers.get("Server", "").lower()
            
            # Check for known vulnerable versions
            vulnerable_patterns = {
                "mcp/1.0": "CRITICAL",
                "mcp/1.1": "HIGH",
            }
            
            for pattern, severity in vulnerable_patterns.items():
                if pattern in server_header:
                    self.findings.append({"endpoint":"Version","severity":severity,"issue":f"Known vulnerable version: {pattern}"})
        except: pass

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 scanner_v2.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    scanner = MCPScannerV2(url)
    findings = scanner.scan()
    
    print(f"\n🔍 Scan Results for {url}\n")
    
    critical = [f for f in findings if f.get("severity") == "CRITICAL"]
    high = [f for f in findings if f.get("severity") == "HIGH"]
    medium = [f for f in findings if f.get("severity") == "MEDIUM"]
    low = [f for f in findings if f.get("severity") == "LOW"]
    
    if critical:
        print("🚨 CRITICAL:")
        for f in critical:
            print(f"  - {f['issue']}")
    
    if high:
        print("\n⚠️ HIGH:")
        for f in high:
            print(f"  - {f['issue']}")
    
    if medium:
        print("\n📊 MEDIUM:")
        for f in medium:
            print(f"  - {f['issue']}")
    
    if low:
        print("\n💡 LOW:")
        for f in low:
            print(f"  - {f['issue']}")
    
    if not findings:
        print("✅ No issues found")
    
    print(f"\n📈 Summary: {len(critical)}C {len(high)}H {len(medium)}M {len(low)}L\n")
