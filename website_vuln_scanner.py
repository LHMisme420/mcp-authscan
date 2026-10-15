#!/usr/bin/env python3
import requests
from urllib.parse import urljoin, urlparse
import re
import json

print("[*] K Health Website Vulnerability Scanner\n")

base_url = "https://khealth.com"

# Get the homepage
print("[*] Fetching homepage...")
r = requests.get(base_url, timeout=10)
html = r.text

print("[✓] Homepage loaded\n")

# 1. Check for sensitive data leaks in HTML
print("=" * 60)
print("[1] Checking for Sensitive Data in Frontend Code")
print("=" * 60)

patterns = {
    "API Keys": r'(?:api[_-]?key|apiKey|API_KEY)["\']?\s*[:=]\s*["\']([^"\']+)',
    "Private Keys": r'(?:private[_-]?key|privateKey)["\']?\s*[:=]\s*["\']([^"\']+)',
    "Tokens": r'(?:token|auth_token|access_token)["\']?\s*[:=]\s*["\']([A-Za-z0-9._-]{20,})',
    "Email addresses": r'([a-zA-Z0-9._%+-]+@khealth\.com)',
    "AWS credentials": r'(?:AKIA[0-9A-Z]{16})',
    "Google API keys": r'AIza[0-9A-Za-z\-_]{35}',
}

for pattern_type, pattern in patterns.items():
    matches = re.findall(pattern, html)
    if matches:
        print(f"\n[!] Found {pattern_type}:")
        for match in set(matches)[:5]:
            print(f"    {match}")

# 2. Check for XSS vulnerabilities
print("\n" + "=" * 60)
print("[2] Testing for XSS Vulnerabilities")
print("=" * 60)

xss_test = "<script>alert('xss')</script>"
endpoints_to_test = [
    "/search",
    "/api/search",
    "/symptoms",
    "/find-doctor",
    "/provider",
]

for endpoint in endpoints_to_test:
    try:
        test_url = urljoin(base_url, endpoint) + f"?q={xss_test}"
        r = requests.get(test_url, timeout=5)
        if xss_test in r.text:
            print(f"[!] Potential XSS on {endpoint}")
    except:
        pass

# 3. Check for CSRF vulnerabilities
print("\n" + "=" * 60)
print("[3] Looking for CSRF tokens")
print("=" * 60)

csrf_patterns = [
    r'<input[^>]*name=["\']_csrf["\']',
    r'<input[^>]*name=["\']csrf["\']',
    r'X-CSRF-Token',
    r'csrf_token',
]

for pattern in csrf_patterns:
    if re.search(pattern, html, re.IGNORECASE):
        print(f"[!] Found CSRF protection: {pattern}")

# 4. Check for exposed API endpoints in frontend code
print("\n" + "=" * 60)
print("[4] Extracting API Endpoints from Frontend")
print("=" * 60)

api_patterns = [
    r'(https?://[^\s"\'<>]+(?:/api|/v\d+)[^\s"\'<>]*)',
    r'fetch\(["\']([^"\']+)',
    r'\.get\(["\']([^"\']+)',
    r'\.post\(["\']([^"\']+)',
]

endpoints = set()
for pattern in api_patterns:
    matches = re.findall(pattern, html)
    endpoints.update(matches)

if endpoints:
    print(f"\n[!] Found {len(endpoints)} potential API endpoints:")
    for ep in list(endpoints)[:10]:
        print(f"    {ep}")

# 5. Check for debug/development endpoints
print("\n" + "=" * 60)
print("[5] Looking for Debug/Dev Endpoints")
print("=" * 60)

debug_paths = [
    "/debug",
    "/console",
    "/admin",
    "/test",
    "/staging",
    "/dev",
    "/.env",
    "/config.json",
    "/settings.json",
]

for path in debug_paths:
    try:
        r = requests.get(urljoin(base_url, path), timeout=5, allow_redirects=False)
        if r.status_code < 400:
            print(f"[{r.status_code}] {path}")
    except:
        pass

# 6. Check for information disclosure in headers
print("\n" + "=" * 60)
print("[6] Analyzing Response Headers")
print("=" * 60)

r = requests.get(base_url)
headers_to_check = [
    'Server',
    'X-Powered-By',
    'X-AspNet-Version',
    'X-Runtime-Version',
    'X-Debug',
    'X-Forwarded-For',
]

for header in headers_to_check:
    if header in r.headers:
        print(f"[!] {header}: {r.headers[header]}")

print("\n[✓] Scan complete")

