#!/usr/bin/env python3
import requests
import socket

print("[*] Anthropic Infrastructure Enumeration\n")

subdomains = [
    "api", "app", "web", "mobile", "docs", "blog",
    "status", "health", "monitoring", "internal",
    "dev", "staging", "test", "admin",
    "auth", "oauth", "login", "account",
    "cdn", "static", "files", "downloads",
    "support", "security", "abuse", "report",
    "graphql", "rest", "grpc", "webhook",
    "claude", "console", "dashboard", "studio",
]

print("[*] Testing Anthropic subdomains:\n")
found = []

for sub in subdomains:
    domain = f"{sub}.anthropic.com"
    try:
        ip = socket.gethostbyname(domain)
        print(f"[✅] {domain} -> {ip}")
        found.append(domain)
    except:
        pass

print(f"\n[✓] Found {len(found)} subdomains\n")

# Test API endpoints
print("[*] Testing endpoints on found subdomains:\n")

endpoints = [
    "/api",
    "/api/v1",
    "/graphql",
    "/health",
    "/status",
    "/version",
    "/info",
    "/.well-known/openid-configuration",
]

for domain in found[:5]:
    for ep in endpoints:
        try:
            r = requests.get(f"https://{domain}{ep}", timeout=3, verify=False)
            if r.status_code < 500:
                print(f"[{r.status_code}] https://{domain}{ep}")
                if r.status_code == 200 and len(r.text) < 300:
                    print(f"      {r.text[:100]}")
        except:
            pass

