from datetime import datetime, timezone
import requests
import json
import hashlib

class AuthorizedMCPScanner:
    """
    MCP Scanner with AUTH REMEDIATION.
    
    Key difference from v3:
    - CORS * is only CRITICAL if endpoint accepts requests WITHOUT auth
    - CORS * is SAFE if endpoint requires Authorization header (token-based)
    - Filters false positives on public endpoints (/health, /status, /openapi.json)
    """
    
    def __init__(self, timeout=3):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def _detect_auth_requirement(self, url, endpoint="/tools/list"):
        """
        Detect if endpoint requires authentication.
        Returns: ("none", "cookie", "token", "unknown")
        """
        try:
            # Test 1: No auth at all
            resp_no_auth = self.session.get(f"{url}{endpoint}", timeout=self.timeout)
            
            # Test 2: With dummy bearer token
            resp_with_token = self.session.get(
                f"{url}{endpoint}",
                headers={"Authorization": "Bearer dummy-token-12345"},
                timeout=self.timeout
            )
            
            # Test 3: Check for Set-Cookie (session-based auth)
            resp_check_cookie = self.session.get(f"{url}{endpoint}", timeout=self.timeout)
            has_cookie = "Set-Cookie" in resp_check_cookie.headers or "set-cookie" in resp_check_cookie.headers
            
            # Logic:
            # - If 401/403 without auth but 200 with token → token-based auth
            # - If 200 without auth and has Set-Cookie → cookie-based auth
            # - If 200 without auth, no Set-Cookie → no auth required
            
            if resp_no_auth.status_code in [401, 403]:
                if resp_with_token.status_code == 200:
                    return "token"
                return "unknown"
            elif resp_no_auth.status_code == 200:
                if has_cookie:
                    return "cookie"
                return "none"
            else:
                return "unknown"
        
        except Exception as e:
            return "unknown"
    
    def _is_public_endpoint(self, endpoint):
        """Check if endpoint is intentionally public"""
        public_patterns = [
            "/health",
            "/status",
            "/ping",
            "/openapi.json",
            "/swagger",
            "/.well-known",
            "/version",
            "/info"
        ]
        return any(endpoint.startswith(p) for p in public_patterns)
    
    def check_cors_accurate(self, url):
        """
        Test CORS with AUTH REMEDIATION.
        
        CRITICAL: CORS * + no-auth endpoint (exploitable cross-origin token theft)
        HIGH: CORS * + cookie-based auth (exploitable session hijacking)
        LOW: CORS * + token-based auth (NOT exploitable; token in header, not cookie)
        INFO: CORS * + public endpoint (intentional, no security impact)
        """
        findings = []
        
        try:
            # Test which endpoints have CORS *
            endpoints_to_test = ["/initialize", "/tools/list", "/tools/call", "/resources/list", "/sse"]
            
            for endpoint in endpoints_to_test:
                try:
                    # 1. Check if CORS header exists
                    resp = self.session.options(
                        f"{url}{endpoint}",
                        headers={"Origin": "https://attacker.com"},
                        timeout=self.timeout
                    )
                    
                    cors_header = resp.headers.get("Access-Control-Allow-Origin", "")
                    
                    if cors_header == "*":
                        # 2. Check if endpoint is public
                        if self._is_public_endpoint(endpoint):
                            findings.append({
                                "endpoint": endpoint,
                                "severity": "INFO",
                                "issue": "CORS wildcard on public endpoint (intentional)",
                                "auth_required": False,
                                "exploitable": False,
                                "header_value": cors_header,
                                "evidence": "Public endpoint pattern"
                            })
                            continue
                        
                        # 3. Detect auth requirement
                        auth_type = self._detect_auth_requirement(url, endpoint)
                        
                        if auth_type == "none":
                            # No auth required = CRITICAL
                            findings.append({
                                "endpoint": endpoint,
                                "severity": "CRITICAL",
                                "issue": "CORS wildcard + unauthenticated endpoint (cross-origin token theft)",
                                "auth_required": False,
                                "auth_type": "none",
                                "exploitable": True,
                                "header_value": cors_header,
                                "evidence": "Endpoint accepts requests without Authorization header",
                                "attack_chain": "1. Attacker hosts malicious page\n2. Victim visits page\n3. Malicious JS makes cross-origin request to this endpoint\n4. Browser includes victim's cookies/credentials\n5. Attacker exfiltrates MCP tool output"
                            })
                        
                        elif auth_type == "cookie":
                            # Cookie-based auth = HIGH (session hijacking possible)
                            findings.append({
                                "endpoint": endpoint,
                                "severity": "HIGH",
                                "issue": "CORS wildcard + cookie-based auth (session hijacking risk)",
                                "auth_required": True,
                                "auth_type": "cookie",
                                "exploitable": True,
                                "header_value": cors_header,
                                "evidence": "Endpoint uses cookie-based authentication; CORS * allows cross-origin requests with credentials",
                                "attack_chain": "1. Attacker hosts malicious page\n2. Victim visits page while logged in\n3. Malicious JS makes cross-origin request\n4. Browser includes victim's cookies\n5. Attacker can call tools on victim's behalf"
                            })
                        
                        elif auth_type == "token":
                            # Token-based auth = SAFE (tokens in Authorization header, not affected by CORS)
                            findings.append({
                                "endpoint": endpoint,
                                "severity": "INFO",
                                "issue": "CORS wildcard with token-based auth (safe; tokens not affected by CORS policy)",
                                "auth_required": True,
                                "auth_type": "token",
                                "exploitable": False,
                                "header_value": cors_header,
                                "evidence": "Endpoint requires Authorization header; tokens are NOT sent by browser CORS mechanism",
                                "rationale": "CORS policy only affects cookie-based auth and requests that include credentials by default. Token-based auth (Authorization header) is NOT vulnerable to CORS exploitation."
                            })
                        
                        else:
                            # Unknown auth type = flag as MEDIUM (conservative)
                            findings.append({
                                "endpoint": endpoint,
                                "severity": "MEDIUM",
                                "issue": "CORS wildcard with unknown auth requirement",
                                "auth_required": "unknown",
                                "auth_type": "unknown",
                                "exploitable": "unknown",
                                "header_value": cors_header,
                                "evidence": "Could not determine auth requirement; manual review needed"
                            })
                
                except Exception as e:
                    pass
        
        except Exception as e:
            pass
        
        return findings
    
    def check_rate_limiting(self, url):
        """Test rate limiting"""
        findings = []
        try:
            for i in range(10):
                resp = self.session.get(f"{url}/initialize", timeout=self.timeout)
                if resp.status_code == 429:
                    return findings  # Rate limiting detected
            
            findings.append({
                "endpoint": "Rate Limiting",
                "severity": "HIGH",
                "issue": "No rate limiting detected; DoS possible",
                "requests_before_limit": 10,
                "evidence": "Made 10 requests, no 429 response"
            })
        except Exception as e:
            pass
        
        return findings
    
    def check_headers(self, url):
        """Check for information disclosure in headers"""
        findings = []
        try:
            resp = self.session.get(f"{url}/initialize", timeout=self.timeout)
            
            suspicious_headers = [
                "Server", "X-Powered-By", "X-AspNet-Version",
                "X-Runtime", "X-Version", "X-MCP-Version"
            ]
            
            for header in suspicious_headers:
                if header in resp.headers:
                    findings.append({
                        "endpoint": "Headers",
                        "severity": "MEDIUM",
                        "issue": f"Version information disclosed in {header}",
                        "value": resp.headers[header],
                        "evidence": f"Response header {header}: {resp.headers[header]}"
                    })
        except Exception as e:
            pass
        
        return findings
    
    def check_oauth_dcr_bypass(self, url):
        """Test OAuth Dynamic Client Registration for unvalidated redirect_uri"""
        findings = []
        dangerous_uris = [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "//attacker.com",
            "http://127.0.0.1:9999"
        ]
        
        try:
            for uri in dangerous_uris:
                payload = {"redirect_uris": [uri], "client_name": "test"}
                resp = self.session.post(f"{url}/register", json=payload, timeout=self.timeout)
                
                if resp.status_code in [200, 201]:
                    try:
                        data = resp.json()
                        if "client_id" in data and uri in data.get("redirect_uris", []):
                            findings.append({"endpoint": "/register", "severity": "CRITICAL", "issue": f"Unvalidated redirect_uri: {uri}"})
                            break
                    except:
                        pass
        except:
            pass
        return findings
    
    def check_oauth_xss_sink(self, url):
        """Test OAuth authorization endpoint for XSS"""
        findings = []
        try:
            resp = self.session.get(f"{url}/authorize", params={"client_id": "test", "redirect_uri": "javascript:alert(1)"}, timeout=self.timeout, allow_redirects=False)
            if "javascript:" in resp.text:
                findings.append({"endpoint": "/authorize", "severity": "CRITICAL", "issue": "XSS sink in redirect"})
        except:
            pass
        return findings
    
    def scan_server(self, url, server_name):
        """Complete scan with auth-aware findings"""
        results = {
            "server": server_name,
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }
        }
        
        try:
            findings = (
                self.check_oauth_dcr_bypass(url) +
                self.check_oauth_xss_sink(url) +
                self.check_cors_accurate(url) +
                self.check_rate_limiting(url) +
                self.check_headers(url)
            )
            
            results["findings"] = findings
            
            # Count severities
            for finding in findings:
                severity = finding.get("severity", "UNKNOWN").lower()
                if severity == "critical":
                    results["summary"]["critical"] += 1
                elif severity == "high":
                    results["summary"]["high"] += 1
                elif severity == "medium":
                    results["summary"]["medium"] += 1
                elif severity == "low":
                    results["summary"]["low"] += 1
                elif severity == "info":
                    results["summary"]["info"] += 1
        
        except Exception as e:
            results["error"] = str(e)
        
        return results

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        servers = [(f"Server{i}", sys.argv[i]) for i in range(1, len(sys.argv))]
    else:
        servers = [
            ("LocalTest", "http://localhost:5001")
        ]
    
    scanner = AuthorizedMCPScanner(timeout=3)
    
    for server_name, url in servers:
        print(f"\n🔍 Scanning {server_name} ({url})...")
        result = scanner.scan_server(url, server_name)
        
        print(json.dumps(result, indent=2))
        
        # Summary
        s = result["summary"]
        print(f"\n📊 {server_name}: C:{s['critical']} H:{s['high']} M:{s['medium']} L:{s['low']} I:{s['info']}")

    def check_oauth_dcr_bypass(self, url):
        """
        Test OAuth Dynamic Client Registration for unvalidated redirect_uri.
        Exploitable if: /register accepts dangerous protocols without validation.
        """
        findings = []
        
        # Payloads that should be blocked
        dangerous_uris = [
            "javascript:alert(1)",
            "javascript:void(0)",
            "data:text/html,<script>alert(1)</script>",
            "//attacker.com",
            "http://127.0.0.1:9999",
            "file:///etc/passwd"
        ]
        
        try:
            # Attempt to register malicious OAuth client
            for uri in dangerous_uris:
                payload = {
                    "redirect_uris": [uri],
                    "client_name": "test-client"
                }
                
                resp = self.session.post(
                    f"{url}/register",
                    json=payload,
                    timeout=self.timeout
                )
                
                # If 200/201 and returns client_id = unvalidated registration
                if resp.status_code in [200, 201]:
                    try:
                        data = resp.json()
                        if "client_id" in data and "redirect_uris" in data:
                            # Check if our dangerous URI was accepted
                            if uri in data.get("redirect_uris", []):
                                findings.append({
                                    "endpoint": "/register",
                                    "severity": "CRITICAL",
                                    "issue": f"Unvalidated redirect_uri accepted: {uri}",
                                    "attack_vector": f"Attacker can register client with {uri}, trigger XSS via authorization endpoint",
                                    "exploitable": True,
                                    "payload": uri,
                                    "response": data,
                                    "evidence": f"POST /register with redirect_uri={uri} returned 200 with client_id"
                                })
                                break  # Found one, no need to test others
                    except:
                        pass
        
        except Exception as e:
            pass
        
        return findings

    def check_oauth_xss_sink(self, url):
        """
        Test if authorization endpoint uses XSS sink for redirect_uri.
        Look for: window.location.href, location.href, redirect patterns
        """
        findings = []
        
        try:
            # Test with XSS payload in code parameter (common in OAuth flows)
            resp = self.session.get(
                f"{url}/authorize",
                params={
                    "client_id": "test",
                    "redirect_uri": "javascript:alert('xss')",
                    "response_type": "code"
                },
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Check if our payload appears in response unescaped
            if "javascript:" in resp.text and "alert" in resp.text:
                findings.append({
                    "endpoint": "/authorize",
                    "severity": "HIGH",
                    "issue": "XSS sink in authorization redirect",
                    "attack_vector": "Dangerous redirect_uri reflected in response without escaping",
                    "evidence": "XSS payload reflected in /authorize response"
                })
        
        except Exception as e:
            pass
        
        return findings
