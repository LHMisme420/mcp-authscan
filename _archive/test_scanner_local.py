"""Local test version - deduplicated findings"""
import requests
import json
import sys

TIMEOUT = 3
mcp_endpoints = ['/mcp', '/sse', '/message', '/tools/list']

def check_cors_vulnerabilities(server_url):
    """Check for CORS origin reflection + credentials vulnerabilities"""
    affected_endpoints = []
    
    # Test both vectors - if endpoints are identical, they're one finding
    for endpoint in mcp_endpoints:
        try:
            # Test with any origin - if it reflects with credentials, it's vulnerable
            test_origin = 'https://attacker-test.invalid'
            headers = {'Origin': test_origin, 'Access-Control-Request-Method': 'POST'}
            res = requests.options(f'{server_url}{endpoint}', headers=headers, timeout=TIMEOUT)
            
            cors_origin = res.headers.get('Access-Control-Allow-Origin', '')
            credentials = res.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            # Both origin reflection + credentials = one vulnerability
            if cors_origin == test_origin and credentials == 'true':
                affected_endpoints.append(endpoint)
        except:
            pass
    
    if affected_endpoints:
        return [('cors_origin_credentials_reflection', 'CRITICAL', affected_endpoints)]
    return []

def scan_server(server):
    """Scan a single MCP server"""
    server_name = server['name']
    server_url = server['url']
    findings = []
    
    try:
        findings.extend(check_cors_vulnerabilities(server_url))
    except:
        pass
    
    return findings

if __name__ == '__main__':
    with open('test_servers.json', 'r') as f:
        servers = json.load(f)
    
    print(f"Scanning {len(servers)} servers...\n")
    
    for server in servers:
        findings = scan_server(server)
        print(f"{server['name']}: {len(findings)} vulnerability(ies) found")
        for vector, severity, endpoints in findings:
            print(f"  [{severity}] {vector}")
            print(f"    Affected endpoints: {', '.join(endpoints)}")
        print()
