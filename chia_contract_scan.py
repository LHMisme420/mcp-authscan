#!/usr/bin/env python3
import requests

print("[*] Scanning for Chialisp contract vulnerabilities\n")

# Common Chia contract endpoints
endpoints = [
    "https://api.chia.net/contracts",
    "https://api.chia.net/nft",
    "https://api.chia.net/dids",
    "https://mainnet.chia.net/api/contracts",
]

# Vulnerability patterns in Chialisp
vulns = {
    "Unchecked conditions": ["(if condition"],
    "Hardcoded values": ["(quote", "(= amount"],
    "Missing validation": ["(>)", "(<)", "(=)"],
}

print("[*] Testing contract API endpoints:\n")

for endpoint in endpoints:
    try:
        r = requests.get(endpoint, timeout=5)
        print(f"[{r.status_code}] {endpoint}")
        if r.status_code == 200:
            print(f"    ✅ Accessible - {len(r.text)} bytes")
    except:
        pass

print("\n[*] Chialisp vulnerability patterns to check:")
for vuln, patterns in vulns.items():
    print(f"  - {vuln}: {patterns}")

