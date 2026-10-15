#!/usr/bin/env python3
import requests
import re
import json

print("[*] Extracting auth tokens from K Health frontend\n")

# Get the main page
print("[1] Fetching khealth.com homepage...")
r = requests.get("https://khealth.com", timeout=10)
html = r.text

# Look for API keys, tokens, credentials in JavaScript
patterns = {
    "JWT tokens": r'(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)',
    "Bearer tokens": r'Bearer\s+([A-Za-z0-9_-]+)',
    "API keys": r'(?:api[_-]?key|apiKey|API_KEY)["\']?\s*[:=]\s*["\']([^"\']+)',
    "Auth headers": r'Authorization["\']?\s*[:=]\s*["\']([^"\']+)',
    "Tokens in JSON": r'"token"\s*:\s*"([^"]+)"',
    "Access tokens": r'"accessToken"\s*:\s*"([^"]+)"',
    "x-wg-token": r'x-wg-token["\']?\s*[:=]\s*["\']([^"\']+)',
}

print("[✓] Page loaded\n")

for pattern_name, pattern in patterns.items():
    matches = re.findall(pattern, html)
    if matches:
        print(f"[!] Found {pattern_name}:")
        for match in set(matches)[:5]:  # Show unique matches
            print(f"    {match}")
        print()

# Look for config/env variables
print("[2] Looking for config in page source...")
config_patterns = [
    r'window\.__[A-Z_]+\s*=\s*({[^}]+})',
    r'const\s+config\s*=\s*({[^}]+})',
    r'export\s+const\s+[A-Z_]+\s*=\s*({[^}]+})',
]

for pattern in config_patterns:
    matches = re.findall(pattern, html)
    if matches:
        print(f"[!] Found config objects: {len(matches)}")
        for match in matches[:2]:
            print(f"    {match[:200]}")
        print()

# Extract JavaScript files that might contain tokens
print("[3] Looking for JavaScript files...")
js_files = re.findall(r'src=["\'](https?://[^\'"]+\.js)["\']', html)
print(f"[✓] Found {len(set(js_files))} JavaScript files")

# Save for manual inspection
with open("khealth_js_files.json", "w") as f:
    json.dump(list(set(js_files)), f, indent=2)
print("Saved to khealth_js_files.json\n")

# Try to find authentication endpoint
print("[4] Looking for auth endpoints in page...")
auth_patterns = [
    r'(?:login|auth|signin)["\']?\s*[:=]\s*["\'](/[^"\']+)',
    r'(https?://[^\s"\']+(?:login|auth|signin)[^\s"\']*)',
]

for pattern in auth_patterns:
    matches = re.findall(pattern, html)
    if matches:
        print(f"[!] Found auth endpoints:")
        for match in set(matches)[:5]:
            print(f"    {match}")

