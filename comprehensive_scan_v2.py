import requests
import re
from scanner_v2 import MCPScannerV2
from datetime import datetime

servers = []

print("Discovering servers...\n")

# Official registry
r = requests.get("https://registry.modelcontextprotocol.io/v0.1/servers", timeout=10)
data = r.json()
for item in data.get("servers", []):
    server = item.get("server", {})
    name = server.get("name", "unknown")
    for remote in server.get("remotes", []):
        if remote.get("type") == "streamable-http":
            url = remote.get("url")
            servers.append({"name": name, "url": url})

# GitHub awesome
r = requests.get("https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md", timeout=10)
content = r.text
pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
matches = re.findall(pattern, content)
skip_patterns = ['img.shields', '.svg', 'reddit', 'discord', 'twitter', 'badge']
for name, url in matches:
    skip = any(re.search(p, url, re.IGNORECASE) for p in skip_patterns)
    if not skip and '/mcp' in url.lower():
        servers.append({"name": name.strip(), "url": url})

# Deduplicate
seen = set()
unique = []
for s in servers:
    key = s.get("url")
    if key and key not in seen:
        seen.add(key)
        unique.append(s)

print(f"Scanning {len(unique)} servers with expanded tests...\n")
print("-" * 60)

results = {}
critical = 0
high = 0
medium = 0

for i, server in enumerate(unique, 1):
    url = server.get("url")
    name = server.get("name")
    
    try:
        scanner = MCPScannerV2(url)
        findings = scanner.scan()
        
        c = len([f for f in findings if f.get("severity") == "CRITICAL"])
        h = len([f for f in findings if f.get("severity") == "HIGH"])
        m = len([f for f in findings if f.get("severity") == "MEDIUM"])
        
        critical += c
        high += h
        medium += m
        
        if findings:
            status = f"⚠️  {c}C {h}H {m}M"
        else:
            status = "✅"
        
        print(f"[{i:3d}/{len(unique)}] {status}")
        results[name] = findings
    except:
        print(f"[{i:3d}/{len(unique)}] ❌")

print("-" * 60)
print(f"\n📊 COMPREHENSIVE V2 RESULTS")
print(f"Total: {len(unique)} | CRITICAL: {critical} | HIGH: {high} | MEDIUM: {medium}")
print(f"Score: {100*(len(unique)-critical-high)//len(unique)}%\n")

import json
with open("comprehensive_scan_v2_full.json", "w") as f:
    json.dump({
        "timestamp": datetime.now().isoformat(),
        "total": len(unique),
        "critical": critical,
        "high": high,
        "medium": medium,
        "findings": results
    }, f, indent=2)

print("💾 Saved to comprehensive_scan_v2_full.json")
