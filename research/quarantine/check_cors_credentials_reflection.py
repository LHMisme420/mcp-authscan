"""Check 2: CORS credentials reflection pair via preflight"""
import requests
import json
import sys

def check_cors_credentials_reflection(server_url):
    """
    Test for credential-leaking CORS via preflight (OPTIONS).
    Returns: findings list, or exits with code 3 if unreachable.
    """
    findings = []
    mcp_endpoints = ['/mcp', '/sse', '/message', '/tools/list']
    
    for endpoint in mcp_endpoints:
        try:
            # CORS preflight: OPTIONS with Origin header
            test_origin = 'https://attacker-test.invalid'
            headers = {
                'Origin': test_origin,
                'Access-Control-Request-Method': 'POST'
            }
            
            res = requests.options(
                f'{server_url}{endpoint}',
                headers=headers,
                timeout=3
            )
            
            cors_origin = res.headers.get('Access-Control-Allow-Origin', '')
            credentials = res.headers.get('Access-Control-Allow-Credentials', '').lower()
            
            # VULNERABLE: reflects origin + allows credentials on real endpoint
            if cors_origin == test_origin and credentials == 'true':
                findings.append({
                    'vector': 'cors_credentials_reflection',
                    'severity': 'CRITICAL',
                    'endpoint': endpoint,
                    'description': f'Credentials leakage on {endpoint}: reflects origin + allows credentials',
                    'evidence': {
                        'test_origin': test_origin,
                        'origin_reflected': cors_origin == test_origin,
                        'credentials_allowed': credentials == 'true'
                    }
                })
        
        except requests.exceptions.ConnectionError:
            print(f"[ERROR] Server unreachable at {server_url}")
            sys.exit(3)
        except requests.exceptions.Timeout:
            print(f"[ERROR] Server timeout at {server_url}")
            sys.exit(3)
        except Exception as e:
            pass
    
    return findings

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python check_cors_credentials_reflection.py <server_url>")
        sys.exit(1)
    
    server = sys.argv[1]
    results = check_cors_credentials_reflection(server)
    
    print(f"Testing: {server}")
    if results:
        print(f"[FAIL] Found {len(results)} vulnerability(ies):")
        for finding in results:
            print(f"  - {finding['vector']}: {finding['severity']} on {finding['endpoint']}")
    else:
        print("[PASS] No credentials reflection found")
    
    print(f"\nFull output:\n{json.dumps(results, indent=2)}")
