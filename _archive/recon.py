#!/usr/bin/env python3
import requests
import json
from urllib.parse import urljoin

def recon_target(base_url):
    """Enumerate target endpoints and gather intelligence"""
    
    print(f"[*] Reconnaissance: {base_url}\n")
    
    endpoints = []
    
    # Common API endpoints to test
    paths = [
        '/api', '/api/v1', '/api/v2',
        '/users', '/user', '/profile', '/me',
        '/auth', '/login', '/register', '/oauth',
        '/data', '/files', '/payment', '/billing',
        '/admin', '/config', '/health', '/status',
        '/openapi.json', '/swagger.json', '/docs', '/api-docs',
        '/.well-known/openapi.json',
    ]
    
    for path in paths:
        try:
            url = urljoin(base_url, path)
            res = requests.head(url, timeout=3, allow_redirects=False)
            if res.status_code < 500:
                endpoints.append({
                    'path': path,
                    'status': res.status_code,
                    'type': 'exists' if res.status_code < 400 else 'redirect/error'
                })
                print(f"  [{res.status_code}] {path}")
        except:
            pass
    
    # Save endpoints for exploitation
    with open('discovered_endpoints.json', 'w') as f:
        json.dump(endpoints, f)
    
    print(f"\n✅ Found {len(endpoints)} endpoints")
    return endpoints

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else 'https://api.example.com'
    recon_target(target)
