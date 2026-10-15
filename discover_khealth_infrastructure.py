#!/usr/bin/env python3
import requests
import socket
import json

print("[*] K Health Infrastructure Discovery\n")

# Common subdomains for health tech companies
subdomains = [
    "api", "app", "web", "mobile", "dev", "staging", "test", "qa", 
    "admin", "internal", "partner", "integrations", "webhooks",
    "cdn", "static", "media", "images", "files", "storage",
    "auth", "login", "oauth", "oidc", "saml",
    "docs", "swagger", "openapi", "graphql",
    "metrics", "monitoring", "logs", "debug",
    "health", "status", "ping", "heartbeat",
    "ai", "ml", "analytics", "insights",
    "provider", "doctor", "patient", "user",
    "claims", "billing", "payments", "invoice",
    "ehr", "fhir", "hipaa", "compliance",
    "aws", "gcp", "azure", "infra",
    "vpn", "bastion", "jump", "proxy",
]

print(f"Testing {len(subdomains)} potential subdomains...\n")

found = []

for subdomain in subdomains:
    domain = f"{subdomain}.khealth.com"
    
    try:
        # DNS lookup
        ip = socket.gethostbyname(domain)
        print(f"[✅] {domain} -> {ip}")
        found.append(domain)
        
        # Try to connect
        try:
            r = requests.get(f"https://{domain}", timeout=3, allow_redirects=False)
            print(f"    Status: {r.status_code}")
        except:
            pass
    except socket.gaierror:
        pass
    except Exception as e:
        pass

print(f"\n[✓] Found {len(found)} valid subdomains:")
for domain in found:
    print(f"  - {domain}")

# Also try direct IP scanning for open ports
print("\n[*] Checking for common services on found subdomains...\n")

for domain in found[:5]:  # Test first 5
    print(f"[*] {domain}")
    paths = [
        "/graphql",
        "/api",
        "/docs",
        "/.well-known/openid-configuration",
        "/health",
        "/status",
        "/metrics",
    ]
    
    for path in paths:
        try:
            r = requests.get(f"https://{domain}{path}", timeout=3, allow_redirects=False)
            if r.status_code < 500:
                print(f"    [{r.status_code}] {path}")
        except:
            pass

