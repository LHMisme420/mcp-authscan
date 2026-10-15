#!/usr/bin/env python3
import requests
import json

print("[*] Comprehensive K Health Endpoint Enumeration\n")

# Common unauthenticated endpoints
endpoints = [
    # Health/Status endpoints
    ("https://api.khealth.com/health", "GET"),
    ("https://api.khealth.com/status", "GET"),
    ("https://api.khealth.com/.health", "GET"),
    ("https://api.khealth.com/ping", "GET"),
    
    # API docs/schema
    ("https://api.khealth.com/graphql/schema", "GET"),
    ("https://api.khealth.com/schema", "GET"),
    ("https://api.khealth.com/docs", "GET"),
    ("https://api.khealth.com/api-docs", "GET"),
    
    # Version endpoints
    ("https://api.khealth.com/v0/graphql", "POST"),
    ("https://api.khealth.com/v2/graphql", "POST"),
    ("https://api.khealth.com/api/v1/graphql", "POST"),
    
    # Well-known endpoints
    ("https://api.khealth.com/.well-known/jwks.json", "GET"),
    ("https://api.khealth.com/.well-known/openid-configuration", "GET"),
    
    # Alternative domains
    ("https://khealth.com/api/graphql", "POST"),
    ("https://app.khealth.com/graphql", "POST"),
    ("https://app-api.khealth.com/graphql", "POST"),
    
    # Debugging endpoints
    ("https://api.khealth.com/debug", "GET"),
    ("https://api.khealth.com/metrics", "GET"),
    
    # OTEL alternatives
    ("https://otel-http.khealth.com/traces", "POST"),
    ("https://otel-http.khealth.com/v1/traces", "POST"),
]

print(f"Testing {len(endpoints)} endpoints...\n")

for url, method in endpoints:
    try:
        if method == "GET":
            r = requests.get(url, timeout=5, allow_redirects=False)
        else:
            r = requests.post(url, json={}, timeout=5, allow_redirects=False)
        
        # Only show interesting responses
        if r.status_code < 400 or r.status_code in [401, 403]:
            print(f"[{r.status_code}] {method:4} {url}")
            if r.status_code < 400 and len(r.text) < 500:
                print(f"      Response: {r.text[:200]}")
            elif 'error' in r.text.lower():
                print(f"      Error: {r.text[:200]}")
    except Exception as e:
        pass

