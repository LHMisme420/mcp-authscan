import json

# Load all servers
with open("phase2_servers.json") as f:
    all_servers = json.load(f)

# Load original 728 scanned servers
with open("final_scan_v2.json") as f:
    scanned_data = json.load(f)
    scanned_names = set(scanned_data.get("findings", {}).keys())

print(f"Total discovered: {len(all_servers)}")
print(f"Already scanned: {len(scanned_names)}")

# High-risk keywords
high_risk_keywords = [
    'shell', 'bash', 'exec', 'command', 'rce',
    'sql', 'database', 'db', 'query', 'mysql', 'postgres', 'postgresql',
    'filesystem', 'fs', 'file', 'path',
    'oauth', 'auth', 'oidc', 'jwt',
    'http', 'proxy', 'gateway', 'forward',
    'api', 'github', 'gitlab', 'bitbucket'
]

# Filter
high_risk = []
for server in all_servers:
    name = (server.get("name") or "").lower()
    url = (server.get("url") or "").lower()
    
    # Skip if already scanned
    if server.get("name") in scanned_names:
        continue
    
    # Check keywords
    if any(kw in name or kw in url for kw in high_risk_keywords):
        high_risk.append(server)

print(f"\nHigh-risk candidates: {len(high_risk)}")

# Save first 1300 (to reach ~2000 total with 728)
target_batch = high_risk[:1300]
with open("phase2_highrisk_batch.json", "w") as f:
    json.dump(target_batch, f, indent=2)

print(f"✅ Selected {len(target_batch)} high-risk servers for Phase 2 audit")
print(f"\nTarget: 728 (phase 1) + {len(target_batch)} (phase 2) = {728 + len(target_batch)} total")

# Show sample
print(f"\nFirst 20 Phase 2 targets:")
for i, s in enumerate(target_batch[:20], 1):
    print(f"  {i:3d}. {s['name'][:60]:60s} [{s['source']}]")
