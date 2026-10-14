#!/usr/bin/env python3
"""
VATA Bounty Vulnerability Testing Suite
Systematic testing for common vulnerability patterns + spoofing
"""
import requests
import json
import time
from datetime import datetime
from urllib.parse import urljoin, parse_qs, urlparse
import sys

class BountyTester:
    def __init__(self, target_url, output_file="bounty_findings.json"):
        self.target_url = target_url
        self.output_file = output_file
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def log_finding(self, vuln_type, severity, endpoint, evidence, description):
        """Log a vulnerability finding"""
        finding = {
            'timestamp': datetime.now().isoformat(),
            'type': vuln_type,
            'severity': severity,
            'endpoint': endpoint,
            'description': description,
            'evidence': evidence
        }
        self.findings.append(finding)
        print(f"[{severity}] {vuln_type}: {endpoint}")
        return finding
    
    def test_idor(self, endpoint, param, test_values=[1, 2, 3, 999]):
        """Test for IDOR - try accessing other users' data by modifying IDs"""
        print(f"\n[*] Testing IDOR on {endpoint}...")
        for value in test_values:
            try:
                url = f"{self.target_url}{endpoint}".replace(f"{{{param}}}", str(value))
                res = self.session.get(url, timeout=5)
                
                if res.status_code == 200 and len(res.text) > 100:
                    self.log_finding(
                        'IDOR',
                        'CRITICAL',
                        endpoint,
                        {'url': url, 'status': res.status_code, 'response_size': len(res.text)},
                        f'Accessing {endpoint} with different {param} values returns data'
                    )
            except Exception as e:
                pass
    
    def test_auth_bypass(self, endpoint):
        """Test for authentication bypass"""
        print(f"\n[*] Testing auth bypass on {endpoint}...")
        
        bypass_techniques = [
            {},  # No auth
            {'Authorization': 'Bearer null'},
            {'Authorization': ''},
            {'Authorization': 'null'},
            {'X-API-Key': 'test'},
            {'X-Access-Token': 'test'},
        ]
        
        for headers in bypass_techniques:
            try:
                test_headers = self.session.headers.copy()
                test_headers.update(headers)
                res = requests.get(f"{self.target_url}{endpoint}", headers=test_headers, timeout=5)
                
                if res.status_code < 400:
                    self.log_finding(
                        'AUTH_BYPASS',
                        'CRITICAL',
                        endpoint,
                        {'headers': headers, 'status': res.status_code},
                        f'Endpoint accessible with bypassed authentication'
                    )
            except:
                pass
    
    def test_info_disclosure(self, endpoint):
        """Test for information disclosure"""
        print(f"\n[*] Testing info disclosure on {endpoint}...")
        
        try:
            res = self.session.get(f"{self.target_url}{endpoint}", timeout=5)
            
            # Check for version info
            if any(pattern in res.text.lower() for pattern in ['version', 'v1.', 'v2.', 'api/v', 'build', 'commit']):
                self.log_finding(
                    'INFO_DISCLOSURE',
                    'MEDIUM',
                    endpoint,
                    {'endpoint': endpoint},
                    'Version or system information exposed'
                )
            
            # Check for error details
            if any(pattern in res.text.lower() for pattern in ['exception', 'traceback', 'sql', 'error at line']):
                self.log_finding(
                    'INFO_DISCLOSURE',
                    'HIGH',
                    endpoint,
                    {'endpoint': endpoint},
                    'Detailed error messages exposed'
                )
        except:
            pass
    
    def test_cors(self, endpoint):
        """Test for CORS misconfiguration"""
        print(f"\n[*] Testing CORS on {endpoint}...")
        
        headers = self.session.headers.copy()
        headers['Origin'] = 'https://attacker.com'
        
        try:
            res = requests.get(f"{self.target_url}{endpoint}", headers=headers, timeout=5)
            
            if 'access-control-allow-origin' in str(res.headers).lower():
                allow_origin = res.headers.get('Access-Control-Allow-Origin', '')
                if allow_origin == '*' or 'attacker' in allow_origin:
                    self.log_finding(
                        'CORS',
                        'HIGH',
                        endpoint,
                        {'allow_origin': allow_origin},
                        'CORS allows requests from unauthorized origins'
                    )
        except:
            pass
    
    def test_rate_limit(self, endpoint, requests_count=50):
        """Test for rate limiting"""
        print(f"\n[*] Testing rate limits on {endpoint}...")
        
        success_count = 0
        start = time.time()
        
        for i in range(requests_count):
            try:
                res = self.session.get(f"{self.target_url}{endpoint}", timeout=2)
                if res.status_code < 400:
                    success_count += 1
            except:
                pass
        
        elapsed = time.time() - start
        if success_count == requests_count and elapsed < 5:
            self.log_finding(
                'RATE_LIMIT_BYPASS',
                'HIGH',
                endpoint,
                {'requests': requests_count, 'time': elapsed},
                f'{requests_count} requests in {elapsed:.1f}s - no rate limiting detected'
            )
    
    def test_spoofed_requests(self, endpoint):
        """Test for request spoofing/manipulation"""
        print(f"\n[*] Testing spoofed requests on {endpoint}...")
        
        spoofs = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Original-IP': '127.0.0.1'},
            {'X-Forwarded-Proto': 'https'},
            {'X-Real-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '127.0.0.1'},
        ]
        
        for spoof in spoofs:
            try:
                headers = self.session.headers.copy()
                headers.update(spoof)
                res = requests.get(f"{self.target_url}{endpoint}", headers=headers, timeout=5)
                
                if res.status_code == 200:
                    self.log_finding(
                        'HEADER_SPOOF',
                        'MEDIUM',
                        endpoint,
                        {'spoofed_header': spoof},
                        'Endpoint accepts spoofed request headers'
                    )
            except:
                pass
    
    def save_findings(self):
        """Save findings to file"""
        with open(self.output_file, 'w') as f:
            json.dump(self.findings, f, indent=2)
        print(f"\n✅ Findings saved to {self.output_file}")
    
    def run_full_scan(self, endpoints):
        """Run all tests on provided endpoints"""
        print(f"[*] Starting bounty scan on {self.target_url}")
        
        for endpoint in endpoints:
            self.test_auth_bypass(endpoint)
            self.test_idor(endpoint, 'id')
            self.test_info_disclosure(endpoint)
            self.test_cors(endpoint)
            self.test_rate_limit(endpoint, 20)
            self.test_spoofed_requests(endpoint)
        
        self.save_findings()
        
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Total findings: {len(self.findings)}")
        print(f"Critical: {len([f for f in self.findings if f['severity'] == 'CRITICAL'])}")
        print(f"High: {len([f for f in self.findings if f['severity'] == 'HIGH'])}")
        print(f"{'='*60}")

if __name__ == '__main__':
    # Usage: python3 bounty_vuln_tester.py <target_url> [endpoints_file]
    
    if len(sys.argv) < 2:
        print("Usage: python3 bounty_vuln_tester.py <target_url> [endpoints_file]")
        print("Example: python3 bounty_vuln_tester.py https://api.example.com endpoints.txt")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Default endpoints - customize for your target
    endpoints = [
        '/api/users',
        '/api/profile',
        '/api/data',
        '/api/status',
        '/health',
    ]
    
    # Load from file if provided
    if len(sys.argv) > 2:
        with open(sys.argv[2], 'r') as f:
            endpoints = [line.strip() for line in f if line.strip()]
    
    tester = BountyTester(target)
    tester.run_full_scan(endpoints)
