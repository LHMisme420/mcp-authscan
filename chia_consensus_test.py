#!/usr/bin/env python3
import requests

print("[*] Testing Chia consensus & economic attack vectors\n")

vectors = {
    "Double-spend": "Can same coin be spent twice?",
    "Fee manipulation": "Can fees be avoided/manipulated?",
    "Pool attacks": "Verify pool share difficulty",
    "Proof hijacking": "Can proofs be faked/reused?",
    "Difficulty reset": "Check difficulty adjustment mechanism",
}

print("[*] Attack Vectors to Test:")
for vector, desc in vectors.items():
    print(f"  - {vector}: {desc}")

print("\n[*] Pool API endpoints:")
pool_endpoints = [
    "https://pool.chia.net/api",
    "https://hpool.com/api",
    "https://xchpool.com/api",
]

for pool in pool_endpoints:
    try:
        r = requests.get(pool, timeout=5)
        print(f"[{r.status_code}] {pool}")
    except:
        print(f"[✗] {pool} - unreachable")

