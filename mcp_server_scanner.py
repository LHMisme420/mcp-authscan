#!/usr/bin/env python3
"""
VATA MCP Server Security Scanner - 2000+ server edition
"""
import requests
import json
import time
from datetime import datetime
import sys

API_URL = 'https://mcp-authscan.onrender.com'
ORG_NAME = 'Dashboard-Viewer'
TIMEOUT = 3
MAX_WORKERS = 5  # Concurrent requests

def get_scanner_token():
    try:
        res = requests.post(f'{API_URL}/auth/register', 
            json={'org_name': ORG_NAME},
            timeout=TIMEOUT)
        data = res.json()
        return data.get('access_token')
    except:
        return None

def submit_finding(token, server_name, vector, severity, description):
    try:
        requests.post(f'{API_URL}/api/findings',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'vector_type': f'mcp_{vector}',
                'severity': severity,
                'description': f'[{server_name}] {description}',
                'remediation': 'Enable auth, disable schema endpoints, implement rate limiting'
            },
            timeout=TIMEOUT)
        return True
    except:
        return False

def scan_server(token, server):
    """Scan a single MCP server"""
    server_name = server['name']
    server_url = server['url']
    vulns_found = 0
    
    try:
        # Check 1: Origin/Host header validation
        origin_findings = check_origin_host_validation(server_url)
        for endpoint, vector, severity in origin_findings:
            submit_finding(token, server_name, vector, severity,
                f'{vector} on {endpoint}')
            vulns_found += 1
        
        # Check 2: CORS credentials reflection
        cors_findings = check_cors_credentials_reflection(server_url)
        for endpoint, vector, severity in cors_findings:
            submit_finding(token, server_name, vector, severity,
                f'{vector} on {endpoint}')
            vulns_found += 1
        
        # Test schema disclosure (keep existing check)
        for path in ['/openapi.json', '/docs', '/.well-known/openapi.json']:
            res = requests.get(f'{server_url}{path}', timeout=TIMEOUT)
            if res.status_code < 400 and len(res.text) > 100:
                submit_finding(token, server_name, 'schema_disclosure', 'HIGH',
                    f'API schema exposed at {path}')
                vulns_found += 1
                break
    
    except requests.exceptions.ConnectionError:
        return -1  # Unreachable
    except:
        pass
    
    return vulns_found


def main():
    print("=" * 60)
    print("VATA MCP Server Security Scanner - Batch Mode")
    print("=" * 60)
    
    token = get_scanner_token()
    if not token:
        print("[!] Failed to authenticate")
        sys.exit(1)
    
    # Load servers
    try:
        with open('mcp_servers_to_scan.json', 'r') as f:
            servers = json.load(f)
    except:
        print("[!] No servers found. Run extraction first.")
        sys.exit(1)
    
    print(f"[+] Loaded {len(servers)} servers to scan")
    print(f"[+] Starting scan...\n")
    
    total_vulns = 0
    scanned = 0
    
    for i, server in enumerate(servers, 1):
        vulns = scan_server(token, server)
        total_vulns += vulns
        scanned += 1
        
        if i % 100 == 0:
            print(f"[+] Progress: {i}/{len(servers)} ({vulns} vulns so far)")
    
    print(f"\n" + "=" * 60)
    print(f"Scan complete!")
    print(f"  Scanned: {scanned}/{len(servers)}")
    print(f"  Vulnerabilities found: {total_vulns}")
    print(f"=" * 60)

if __name__ == '__main__':
    main()

def check_origin_host_validation(server_url):
    """Check for Origin/Host header validation vulnerabilities"""
    findings = []
    mcp_endpoints = ['/mcp', '/sse', '/message', '/tools/list']
    
    for endpoint in mcp_endpoints:
        try:
            evil_origin = 'https://evil.example.com'
            headers = {'Origin': evil_origin, 'Access-Control-Request-Method': 'POST'}
            res = requests.options(f'{server_url}{endpoint}', headers=headers, timeout=TIMEOUT)
            
            cors_origin = res.headers.get('Access-Control-Allow-Origin', '')
            credentials = res.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if cors_origin == evil_origin and credentials == 'true':
                findings.append((endpoint, 'origin_reflection_with_credentials', 'CRITICAL'))
        except:
            pass
    
    return findings

def check_cors_credentials_reflection(server_url):
    """Check for CORS credentials reflection vulnerabilities"""
    findings = []
    mcp_endpoints = ['/mcp', '/sse', '/message', '/tools/list']
    
    for endpoint in mcp_endpoints:
        try:
            test_origin = 'https://attacker-test.invalid'
            headers = {'Origin': test_origin, 'Access-Control-Request-Method': 'POST'}
            res = requests.options(f'{server_url}{endpoint}', headers=headers, timeout=TIMEOUT)
            
            cors_origin = res.headers.get('Access-Control-Allow-Origin', '')
            credentials = res.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            if cors_origin == test_origin and credentials == 'true':
                findings.append((endpoint, 'cors_credentials_reflection', 'CRITICAL'))
        except:
            pass
    
    return findings
