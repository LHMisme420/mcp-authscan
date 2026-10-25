import json
import requests
from mcp_authscan.cors import probe_cors_requests
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load Phase 2 target servers
with open("phase2_highrisk_batch.json") as f:
    servers = json.load(f)

print(f"🎯 Phase 2 Scan: {len(servers)} high-risk servers")
print(f"⏱️  Starting at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

results = {
    "timestamp": datetime.now().isoformat(),
    "phase": "2-highrisk",
    "total": len(servers),
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "findings": {}
}

def scan_server(server, idx):
    name = server.get("name", "unknown")
    url = server.get("url", "")
    
    try:
        # Try to connect - 5 sec timeout
        resp = requests.get(url, timeout=5, allow_redirects=False)
        
        # Check headers for info disclosure
        findings = []
        headers = resp.headers
        
        if "Server" in headers:
            findings.append({"severity": "LOW", "issue": f"Server header: {headers['Server']}"})
        
        if "X-Powered-By" in headers:
            findings.append({"severity": "LOW", "issue": f"X-Powered-By: {headers['X-Powered-By']}"})
        
        # Check CORS
        cors = probe_cors_requests(url, timeout=5)
        if cors.is_finding:
            findings.append({"severity": cors.severity, "issue": cors.summary,
                             "details": cors.details})
            results[cors.severity.lower()] += 1
        
        # Rate limiting check
        if not headers.get("X-RateLimit-Limit"):
            findings.append({"severity": "MEDIUM", "issue": "No rate limiting headers"})
            results["medium"] += 1
        
        if findings:
            results["findings"][name] = findings
        
        status = "⚠️ " if findings else "✅"
        print(f"[{idx:4d}/{len(servers)}] {status} {name[:50]:50s}")
        
    except Exception as e:
        print(f"[{idx:4d}/{len(servers)}] ❌ {name[:50]:50s} (timeout/error)")

# Concurrent scan - 10 workers
with ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(scan_server, s, i+1) for i, s in enumerate(servers)]
    for future in as_completed(futures):
        pass

results["secure"] = len(servers) - len(results["findings"])
results["score"] = round((results["secure"] / len(servers)) * 100, 1)

print(f"\n{'='*60}")
print(f"Phase 2 Complete!")
print(f"  Scanned: {len(servers)}")
print(f"  HIGH:    {results['high']}")
print(f"  MEDIUM:  {results['medium']}")
print(f"  Secure:  {results['secure']}")
print(f"  Score:   {results['score']}%")
print(f"{'='*60}")

with open("final_scan_phase2.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Results saved to final_scan_phase2.json")
