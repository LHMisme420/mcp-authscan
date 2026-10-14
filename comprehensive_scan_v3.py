import json
import sys
from scanner_v3 import MCPScannerV3

# Load servers from registry
with open("../mcp-security-registry/data/comprehensive_scan_v2.json") as f:
    servers_data = json.load(f)

# Extract server list - FIXED URL construction
servers = [(name, f"https://{name}") for name in servers_data["findings"].keys()]

# Run concurrent scan (10 at a time)
print(f"Scanning {len(servers)} servers with v3 scanner (concurrent)...")
scanner = MCPScannerV3(max_workers=10, timeout=3)
results = scanner.scan_servers_concurrent(servers)

# Save results
with open("comprehensive_scan_v3_full.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n📊 COMPREHENSIVE V3 RESULTS")
print(f"Total: {results['total']} | CRITICAL: {results['critical']} | HIGH: {results['high']} | MEDIUM: {results['medium']}")
print(f"💾 Saved to comprehensive_scan_v3_full.json")
