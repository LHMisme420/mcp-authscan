from datetime import datetime, timezone
from datetime import datetime, timezone
import requests
from mcp_authscan.cors import probe_cors_requests
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import hashlib

class MCPScannerV3:
    def __init__(self, timeout=3, max_workers=5):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        # Expanded payload library
        self.payloads = {
            'sql_injection': [
                "test'; DROP TABLE--",
                "1' OR '1'='1",
                "admin' --",
                "1'; WAITFOR DELAY '00:00:05'--",
                "1' UNION SELECT NULL--"
            ],
            'command_injection': [
                'test"; eval("x");//',
                "test`whoami`",
                "test$(whoami)",
                "test | cat /etc/passwd",
                "test; id"
            ],
            'path_traversal': [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc/passwd",
                "..%2F..%2F..%2Fetc%2Fpasswd"
            ],
            'xss': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                'javascript:alert(1)',
                '<img src=x onerror=alert(1)>'
            ]
        }

    def check_input_validation(self, url):
        """Test for SQL injection, command injection, path traversal"""
        findings = []
        
        for attack_type, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    resp = self.session.post(
                        f"{url}/tools/call",
                        json={"tool": "test", "input": payload},
                        timeout=self.timeout
                    )
                    
                    # Capture response for analysis
                    response_sig = hashlib.md5(resp.text.encode()).hexdigest()
                    
                    # Check for vulnerability indicators
                    if self._indicates_vulnerability(resp.text, attack_type):
                        findings.append({
                            "endpoint": "Input Validation",
                            "severity": "CRITICAL",
                            "issue": f"No validation on: {payload}",
                            "attack_type": attack_type,
                            "response_signature": response_sig,
                            "response_sample": resp.text[:200]
                        })
                        break  # Found vulnerability, move to next attack type
                except Exception as e:
                    pass
        
        return findings

    def _indicates_vulnerability(self, response, attack_type):
        """Detect if response indicates successful attack"""
        indicators = {
            'sql_injection': ['syntax error', 'sql', 'database error', 'unexpected'],
            'command_injection': ['uid=', 'gid=', 'groups=', 'command not found'],
            'path_traversal': ['root:', 'passwd', 'boot.ini', 'sam'],
            'xss': ['<script>', 'onerror', 'alert']
        }
        
        response_lower = response.lower()
        return any(indicator in response_lower for indicator in indicators.get(attack_type, []))

    def check_cors(self, url):
        """Test CORS configuration"""
        findings = []
        try:
            assessment = probe_cors_requests(
                f"{url}/initialize", timeout=self.timeout, session=self.session
            )
            if assessment.is_finding:
                findings.append({
                    "endpoint": "CORS",
                    "severity": assessment.severity,
                    "issue": assessment.summary,
                    "details": assessment.details,
                })
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
            
            # No 429 after 10 requests
            findings.append({
                "endpoint": "Rate Limiting",
                "severity": "MEDIUM",
                "issue": "No rate limiting detected on endpoints",
                "requests_before_limit": 10
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
                "X-Runtime", "X-Version"
            ]
            
            for header in suspicious_headers:
                if header in resp.headers:
                    findings.append({
                        "endpoint": "Headers",
                        "severity": "LOW",
                        "issue": f"Version disclosed in {header}",
                        "value": resp.headers[header]
                    })
        except Exception as e:
            pass
        
        return findings

    def scan_server(self, url, server_name):
        """Complete scan with response capture"""
        results = {
            "server": server_name,
            "url": url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "findings": [],
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        }
        
        try:
            # Run all checks
            findings = (
                self.check_input_validation(url) +
                self.check_cors(url) +
                self.check_rate_limiting(url) +
                self.check_headers(url)
            )
            
            results["findings"] = findings
            
            # Count severities
            for finding in findings:
                severity = finding["severity"]
                if severity == "CRITICAL":
                    results["critical"] += 1
                elif severity == "HIGH":
                    results["high"] += 1
                elif severity == "MEDIUM":
                    results["medium"] += 1
                elif severity == "LOW":
                    results["low"] += 1
        
        except Exception as e:
            results["error"] = str(e)
        
        return results

    def scan_servers_concurrent(self, servers):
        """Scan multiple servers concurrently"""
        all_results = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total": len(servers),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "findings": {}
        }
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self.scan_server, url, name): (name, url)
                for name, url in servers
            }
            
            completed = 0
            for future in as_completed(futures):
                completed += 1
                name, url = futures[future]
                
                try:
                    result = future.result()
                    all_results["findings"][name] = result["findings"]
                    all_results["critical"] += result["critical"]
                    all_results["high"] += result["high"]
                    all_results["medium"] += result["medium"]
                    
                    status = f"0C {result['high']}H {result['medium']}M"
                    print(f"[{completed:3d}/{len(servers)}] ⚠️  {status}")
                except Exception as e:
                    print(f"[{completed:3d}/{len(servers)}] ❌ {name}: {str(e)}")
        
        return all_results

if __name__ == "__main__":
    import sys
    
    # Test with provided servers
    if len(sys.argv) > 1:
        servers = [(f"Server{i}", sys.argv[i]) for i in range(1, len(sys.argv))]
    else:
        servers = [
            ("test1", "https://sh.inference.ac/mcp"),
            ("test2", "https://mcp.snag.ac/snag")
        ]
    
    scanner = MCPScannerV3(max_workers=5)
    results = scanner.scan_servers_concurrent(servers)
    
    print("\n" + "="*60)
    print(f"📊 RESULTS: {results['total']} servers | C:{results['critical']} H:{results['high']} M:{results['medium']}")
    print(f"💾 Saved to scan_v3_results.json")
    
    with open("scan_v3_results.json", "w") as f:
        json.dump(results, f, indent=2)
