#!/usr/bin/env python3
import requests
import socket

subdomains = [
    "api", "rpc", "node", "wallet", "farmer", "pool", "dex",
    "explorer", "mainnet", "testnet", "staging", "dev",
    "github", "docs", "blog", "status", "cdn", "dns",
    "nft", "tokens", "bridge", "exchange", "market",
    "auth", "login", "admin", "internal", "monitoring",
]

print("[*] Testing Chia subdomains:\n")

found = []
for sub in subdomains:
    domain = f"{sub}.chia.net"
    try:
        ip = socket.gethostbyname(domain)
        print(f"[✅] {domain} -> {ip}")
        found.append(domain)
    except:
        pass

print(f"\n[✓] Found {len(found)} subdomains\n")

# Test API endpoints on found subdomains
print("[*] Testing API endpoints on found subdomains:\n")

for domain in found[:5]:
    endpoints = [
        "/api",
        "/rpc",
        "/graphql",
        "/health",
        "/status",
        "/version",
        "/api/v1",
    ]
    
    for ep in endpoints:
        try:
            r = requests.get(f"https://{domain}{ep}", timeout=3)
            if r.status_code < 500:
                print(f"[{r.status_code}] https://{domain}{ep}")
        except:
            pass

