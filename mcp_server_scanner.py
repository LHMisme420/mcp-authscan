#!/usr/bin/env python3
"""
VATA MCP Server Security Scanner
Tests MCP servers for common vulnerabilities
"""
import requests
import json
import time
from datetime import datetime
import sys

API_URL = 'https://mcp-authscan.onrender.com'
ORG_NAME = 'Dashboard-Viewer'
TIMEOUT = 5

# Test MCP servers (public test instances + common endpoints)
MCP_SERVERS = [
    {'name': 'Local MCP Test', 'url': 'http://localhost:3000'},
    {'name': 'Claude MCP Docs', 'url': 'https://mcp.anthropic.com'},
]

VECTORS = {
    'unauthenticated_access': {
        'paths': ['/tools', '/resources', '/api/tools', '/api/resources'],
        'method': 'GET',
        'severity': 'CRITICAL'
    },
    'schema_disclosure': {
        'paths': ['/openapi.json', '/swagger.json', '/docs', '/api/docs', '/.well-known/openapi.json'],
        'method': 'GET',
        'severity': 'HIGH'
    },
    'info_disclosure': {
        'paths': ['/', '/health', '/status', '/version', '/api/version'],
        'method': 'GET',
        'severity': 'MEDIUM'
    },
    'rate_limit_bypass': {
        'paths': ['/tools'],
        'method': 'GET',
        'requests': 100,
        'severity': 'HIGH'
    },
    'tool_execution_auth_bypass': {
        'paths': ['/tools/execute', '/api/tools/execute'],
        'method': 'POST',
        'payload': {'tool': 'test', 'args': {}},
        'severity': 'CRITICAL'
    },
    'cors_misconfiguration': {
        'paths': ['/tools'],
        'method': 'OPTIONS',
        'severity': 'MEDIUM'
    },
}

def get_scanner_token():
    try:
        res = requests.post(f'{API_URL}/auth/register', 
            json={'org_name': ORG_NAME},
            timeout=TIMEOUT)
        data = res.json()
        return data.get('access_token')
    except Exception as e:
        print(f'[!] Failed to register: {e}')
        return None

def submit_finding(token, server_name, vector, severity, description):
    try:
        requests.post(f'{API_URL}/api/findings',
            headers={'Authorization': f'Bearer {token}'},
            json={
                'vector_type': f'mcp_{vector}',
                'severity': severity,
                'description': f'[{server_name}] {description}',
                'remediation': 'Enable authentication, disable schema endpoints, implement rate limiting'
            },
            timeout=TIMEOUT)
        return True
    except Exception as e:
        print(f'[!] Failed to submit: {e}')
        return False

def test_unauthenticated_access(token, server_name, server_url):
    """Test if MCP endpoints are accessible without auth"""
    found = False
    for path in VECTORS['unauthenticated_access']['paths']:
        try:
            res = requests.get(f'{server_url}{path}', timeout=TIMEOUT)
            if res.status_code < 400:
                print(f'  [VULN] {server_name}: Unauthenticated {path} accessible ({res.status_code})')
                submit_finding(token, server_name, 'unauthenticated_access',
                    VECTORS['unauthenticated_access']['severity'],
                    f'Endpoint {path} accessible without authentication')
                found = True
        except:
            pass
    return found

def test_schema_disclosure(token, server_name, server_url):
    """Test for API schema disclosure"""
    found = False
    for path in VECTORS['schema_disclosure']['paths']:
        try:
            res = requests.get(f'{server_url}{path}', timeout=TIMEOUT)
            if res.status_code < 400 and len(res.text) > 100:
                print(f'  [VULN] {server_name}: Schema exposed at {path}')
                submit_finding(token, server_name, 'schema_disclosure',
                    VECTORS['schema_disclosure']['severity'],
                    f'API schema exposed at {path}')
                found = True
        except:
            pass
    return found

def test_info_disclosure(token, server_name, server_url):
    """Test for information disclosure"""
    found = False
    for path in VECTORS['info_disclosure']['paths']:
        try:
            res = requests.get(f'{server_url}{path}', timeout=TIMEOUT)
            if res.status_code < 400:
                data = res.json() if res.headers.get('content-type', '').startswith('application/json') else {}
                if 'version' in data or 'Version' in str(data):
                    print(f'  [VULN] {server_name}: Version info disclosed at {path}')
                    submit_finding(token, server_name, 'info_disclosure',
                        VECTORS['info_disclosure']['severity'],
                        f'Version/system info disclosed at {path}')
                    found = True
        except:
            pass
    return found

def test_rate_limit_bypass(token, server_name, server_url):
    """Test for rate limit bypass"""
    try:
        start = time.time()
        success_count = 0
        for i in range(10):  # Test 10 requests rapidly
            res = requests.get(f'{server_url}/tools', timeout=TIMEOUT)
            if res.status_code < 400:
                success_count += 1
        elapsed = time.time() - start
        
        if elapsed < 2 and success_count >= 10:  # All succeeded in under 2 seconds
            print(f'  [VULN] {server_name}: Possible rate limit bypass (10 req in {elapsed:.1f}s)')
            submit_finding(token, server_name, 'rate_limit_bypass',
                VECTORS['rate_limit_bypass']['severity'],
                f'Server accepted 10 requests in {elapsed:.1f}s - possible rate limit bypass')
            return True
    except:
        pass
    return False

def test_tool_execution_bypass(token, server_name, server_url):
    """Test for unauthorized tool execution"""
    found = False
    for path in VECTORS['tool_execution_auth_bypass']['paths']:
        try:
            res = requests.post(f'{server_url}{path}',
                json={'tool': 'test', 'args': {}},
                timeout=TIMEOUT)
            if res.status_code < 400:
                print(f'  [VULN] {server_name}: Tool execution without auth at {path}')
                submit_finding(token, server_name, 'tool_execution_bypass',
                    VECTORS['tool_execution_auth_bypass']['severity'],
                    f'Tool execution possible without authentication at {path}')
                found = True
        except:
            pass
    return found

def scan_mcp_server(token, server):
    """Scan a single MCP server"""
    server_name = server['name']
    server_url = server['url']
    
    print(f"\n[*] Scanning: {server_name} ({server_url})")
    
    vulns_found = 0
    
    # Run all tests
    if test_unauthenticated_access(token, server_name, server_url):
        vulns_found += 1
    if test_schema_disclosure(token, server_name, server_url):
        vulns_found += 1
    if test_info_disclosure(token, server_name, server_url):
        vulns_found += 1
    if test_rate_limit_bypass(token, server_name, server_url):
        vulns_found += 1
    if test_tool_execution_bypass(token, server_name, server_url):
        vulns_found += 1
    
    if vulns_found == 0:
        print(f"  [✓] No vulnerabilities found")
    else:
        print(f"  [!] Found {vulns_found} vulnerability/vulnerabilities")
    
    return vulns_found

def main():
    print("=" * 60)
    print("VATA MCP Server Security Scanner")
    print("=" * 60)
    
    token = get_scanner_token()
    if not token:
        print("[!] Failed to authenticate with VATA platform")
        sys.exit(1)
    
    print(f"[+] Authenticated with VATA platform")
    print(f"[+] Scanning {len(MCP_SERVERS)} MCP servers...\n")
    
    total_vulns = 0
    for server in MCP_SERVERS:
        try:
            vulns = scan_mcp_server(token, server)
            total_vulns += vulns
        except Exception as e:
            print(f"[!] Error scanning {server['name']}: {e}")
    
    print(f"\n" + "=" * 60)
    print(f"Scan complete. Total vulnerabilities found: {total_vulns}")
    print(f"=" * 60)

if __name__ == '__main__':
    main()
