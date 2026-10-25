#!/usr/bin/env python3
import requests
import re
import json
from bs4 import BeautifulSoup

print("[*] Extracting Actual API Calls from K Health Website\n")

# Get the homepage and parse for JS files
r = requests.get("https://khealth.com", timeout=10)
html = r.text

# Extract all JS files
js_files = re.findall(r'src=["\'](/_next/static[^\'"]+\.js)["\']', html)
print(f"[*] Found {len(js_files)} JS chunks to analyze\n")

# Download and analyze first few chunks
api_endpoints = set()
api_calls = set()

for js_file in js_files[:10]:  # Analyze first 10 chunks
    try:
        full_url = f"https://khealth.com{js_file}"
        r = requests.get(full_url, timeout=5)
        js_code = r.text
        
        # Look for API endpoints
        patterns = [
            r'https?://[^\s"\']+?(/[a-z0-9/_-]+)',  # URLs
            r'["\'](/api/[^\'"]+)',  # API paths
            r'fetch\(["\']([^\'"]+)',  # fetch calls
            r'\.get\(["\']([^\'"]+)',  # axios/request calls
            r'graphql',  # GraphQL
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code)
            api_endpoints.update(matches)
            
        # Look for specific API calls
        if 'graphql' in js_code.lower():
            print(f"[!] GraphQL calls in {js_file}")
        if 'clienttoken' in js_code:
            print(f"[!] Client token refs in {js_file}")
            
    except Exception as e:
        pass

print("\n[*] Extracted potential endpoints:\n")
for ep in sorted(list(api_endpoints)[:20]):
    if len(ep) > 2:
        print(f"  {ep}")

# Now test these endpoints
print("\n" + "=" * 60)
print("[*] Testing Extracted Endpoints")
print("=" * 60 + "\n")

base_urls = [
    "https://khealth.com",
    "https://api.khealth.com",
    "https://app.khealth.com",
]

test_endpoints = [
    "/api/auth/me",
    "/api/user/profile",
    "/api/graphql",
    "/graphql",
    "/api/health",
    "/health",
    "/api/v1/user",
]

for base in base_urls:
    for endpoint in test_endpoints:
        try:
            r = requests.get(f"{base}{endpoint}", timeout=3, allow_redirects=False)
            if r.status_code < 500:
                print(f"[{r.status_code}] {base}{endpoint}")
                if r.status_code < 400 and len(r.text) < 500:
                    print(f"      {r.text[:100]}")
        except:
            pass

