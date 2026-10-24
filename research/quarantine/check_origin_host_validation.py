"""Check 1: Origin/Host header validation (DNS rebind protection)"""
import requests
import json
import sys

def check_origin_host_validation(server_url):
    """
    Test if server validates Origin/Host headers via CORS preflight (OPTIONS).
    Returns: findings list, or exits with code 3 if server unreachable.
    """
    findings = []
    mcp_endpoints = ['/mcp', '/sse', '/message', '/tools/list']
    
    for endpoint in mcp_endpoints:
        try:
            # CORS preflight: OPTIONS with Origin header
            evil_origin = 'https://evil.example.com'
            headers = {
                'Origin': evil_origin,
                'Access-Control-Request-Method': 'POST'
            }
            
            res = requests.options(
                f'{server_url}{endpoint}',
                headers=headers,
                timeout=3
            )
            
            cors_origin = res.headers.get('Access-Control-Allow-Origin', '')
            credentials = res.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            # VULNERABLE: reflects attacker origin with credentials on real endpoint
            if cors_origin == evil_origin and credentials == 'true':
                findings.append({
                    'vector': 'origin_reflection_with_credentials',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint,
                    'description': f'Origin reflection on {endpoint}: reflects attacker origin with credentials allowed',
                    'evidence': {
                        'sent_origin': evil_origin,
                        'reflected_origin': cors_origin,
                        'allows_credentials': credentials
                    }
                })
        
        except requests.exceptions.ConnectionError:
            # Server unreachable - fatal error
            print(f"[ERROR] Server unreachable at {server_url}")
            sys.exit(3)
        except requests.exceptions.Timeout:
            print(f"[ERROR] Server timeout at {server_url}")
            sys.exit(3)
        except Exception as e:
            # Any other error = unreachable
            pass
    
    return findings

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python check_origin_host_validation.py <server_url>")
        sys.exit(1)
    
    server = sys.argv[1]
    results = check_origin_host_validation(server)
    
    print(f"Testing: {server}")
    if results:
        print(f"[FAIL] Found {len(results)} vulnerability(ies):")
        for finding in results:
            print(f"  - {finding['vector']}: {finding['severity']} on {finding['endpoint']}")
    else:
        print("[PASS] No origin reflection vulnerabilities found")
    
    print(f"\nFull output:\n{json.dumps(results, indent=2)}")
