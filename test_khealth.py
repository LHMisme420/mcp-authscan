#!/usr/bin/env python3
import requests
import json

print("[*] Testing K Health API endpoints...\n")

endpoints = [
    "https://otel-http.khealth.com/clienttoken/v1/traces",
    "https://api.khealth.com/",
    "https://api.khealth.com/v1/",
    "https://api.khealth.com/graphql",
    "https://auth.khealth.com/",
    "https://khealth.com/api/",
]

for url in endpoints:
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)
        print(f"✅ {url}")
        print(f"   Status: {r.status_code}")
        print(f"   Headers: {dict(r.headers)}\n")
    except Exception as e:
        print(f"❌ {url} - {str(e)}\n")
