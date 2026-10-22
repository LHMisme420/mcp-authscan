"""OAuth vulnerability patterns - comprehensive detection"""
import requests
import json

class OAuthPatternDetector:
    """Detect OAuth misconfigurations and vulnerabilities."""
    
    def __init__(self, url, timeout=3):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.findings = []
    
    def check_rate_limiting(self):
        """Test for missing/weak rate limiting."""
        findings = []
        try:
            # Attempt rapid requests
            for i in range(10):
                r = requests.get(self.url + "/", timeout=self.timeout)
                if r.status_code != 429:  # 429 = Too Many Requests
                    continue
                return findings
            
            # If we got here, no rate limit detected
            findings.append({
                "type": "MISSING_RATE_LIMIT",
                "severity": "MEDIUM",
                "message": "Server accepts 10+ rapid requests without 429"
            })
        except:
            pass
        return findings
    
    def check_cors_misconfiguration(self):
        """Test for overly permissive CORS."""
        findings = []
        try:
            headers = {
                "Origin": "https://evil.com"
            }
            r = requests.options(self.url + "/", headers=headers, timeout=self.timeout)
            
            if r.headers.get("Access-Control-Allow-Origin") == "*":
                findings.append({
                    "type": "CORS_WILDCARD",
                    "severity": "HIGH",
                    "message": "CORS allows wildcard origin (*)"
                })
            elif r.headers.get("Access-Control-Allow-Origin") == "https://evil.com":
                findings.append({
                    "type": "CORS_REFLECTION",
                    "severity": "HIGH",
                    "message": "CORS reflects attacker origin"
                })
        except:
            pass
        return findings
    
    def check_redirect_validation(self):
        """Test for OAuth redirect URL validation bypass."""
        findings = []
        try:
            # Test open redirect in callback
            test_urls = [
                self.url + "/?redirect=https://evil.com",
                self.url + "/?return_to=https://evil.com",
                self.url + "/?callback=https://evil.com",
                self.url + "/?next=https://evil.com"
            ]
            
            for test_url in test_urls:
                try:
                    r = requests.get(test_url, allow_redirects=False, timeout=self.timeout)
                    if r.status_code in (301, 302, 303, 307, 308):
                        if "evil.com" in r.headers.get("Location", ""):
                            findings.append({
                                "type": "OPEN_REDIRECT",
                                "severity": "HIGH",
                                "param": test_url.split("=")[0].split("?")[1] if "=" in test_url else "unknown",
                                "message": "OAuth callback vulnerable to open redirect"
                            })
                except:
                    pass
        except:
            pass
        return findings
    
    def check_scope_validation(self):
        """Test for OAuth scope bypass."""
        findings = []
        try:
            # Test overly broad scopes
            suspicious_scopes = [
                "admin", "*", "all", "full_access",
                "read_write_delete", "unrestricted"
            ]
            
            for scope in suspicious_scopes:
                r = requests.get(
                    self.url + f"/auth?scope={scope}",
                    timeout=self.timeout
                )
                if r.status_code == 200:
                    findings.append({
                        "type": "EXCESSIVE_SCOPE",
                        "severity": "MEDIUM",
                        "scope": scope
                    })
                    break
        except:
            pass
        return findings
    
    def check_zero_auth(self):
        """Test for endpoints accessible without authentication."""
        findings = []
        try:
            sensitive_endpoints = [
                "/admin", "/api/admin", "/api/users",
                "/settings", "/config", "/credentials",
                "/servers", "/gateways", "/tools"
            ]
            
            zero_auth_endpoints = []
            for endpoint in sensitive_endpoints:
                try:
                    r = requests.get(
                        self.url + endpoint,
                        timeout=self.timeout
                    )
                    # 200/201 without auth = accessible
                    if r.status_code in (200, 201):
                        zero_auth_endpoints.append(endpoint)
                except:
                    pass
            
            if zero_auth_endpoints:
                findings.append({
                    "type": "ZERO_AUTH_ACCESS",
                    "severity": "CRITICAL",
                    "endpoints": zero_auth_endpoints[:5],
                    "message": f"{len(zero_auth_endpoints)} endpoints accessible without auth"
                })
        except:
            pass
        return findings
    
    def check_credential_exposure(self):
        """Test for exposed credentials in responses."""
        findings = []
        try:
            r = requests.get(self.url + "/.env", timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "ENV_FILE_EXPOSED",
                    "severity": "CRITICAL",
                    "message": ".env file publicly accessible"
                })
            
            r = requests.get(self.url + "/config.json", timeout=self.timeout)
            if r.status_code == 200 and "secret" in r.text.lower():
                findings.append({
                    "type": "CONFIG_EXPOSED",
                    "severity": "CRITICAL",
                    "message": "config.json with secrets publicly accessible"
                })
        except:
            pass
        return findings
    
    def run(self):
        """Run all OAuth pattern checks."""
        all_findings = []
        all_findings.extend(self.check_rate_limiting())
        all_findings.extend(self.check_cors_misconfiguration())
        all_findings.extend(self.check_redirect_validation())
        all_findings.extend(self.check_scope_validation())
        all_findings.extend(self.check_zero_auth())
        all_findings.extend(self.check_credential_exposure())
        return all_findings
