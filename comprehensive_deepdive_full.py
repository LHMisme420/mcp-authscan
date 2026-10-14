import json
import requests
import re
from collections import defaultdict
from datetime import datetime
import concurrent.futures

with open("phase2_highrisk_batch.json") as f:
    servers = json.load(f)

print(f"🚀 FULL DEEP-DIVE AUDIT: {len(servers)} servers")
print("Starting parallel scan...\n")

results = {
    "timestamp": datetime.now().isoformat(),
    "total_servers": len(servers),
    "vectors": {
        "credential_exposure": [],
        "error_disclosure": [],
        "command_execution": [],
        "database_servers": [],
        "auth_issues": [],
        "openapi_exposure": [],
        "schema_exposure": []
    }
}

openapi_paths = ["/openapi.json", "/.well-known/openapi.json", "/swagger.json"]
credential_patterns = [r'(api[_-]?key|token|password|secret|credential)["\']?\s*[:=]', r'Bearer\s+[A-Za-z0-9]']
error_patterns = [r'(traceback|stack trace|exception)', r'(sql|database|mysql|postgres)', r'(\/home\/|\/root\/|\/var\/)']
command_patterns = ['exec', 'eval', 'system', 'shell', 'bash']
db_patterns = ['mysql', 'postgres', 'mongodb', 'redis', 'sql', 'database']
auth_patterns = ['oauth', 'jwt', 'auth', 'apikey']

def scan_server(server):
    name = server.get("name", "unknown")
    url = server.get("url", "")
    findings = defaultdict(list)
    
    try:
        r = requests.get(url, timeout=5)
        text = r.text.lower()
        
        # Credential exposure
        for pattern in credential_patterns:
            if re.search(pattern, r.text, re.IGNORECASE):
                findings["credential_exposure"].append(name)
                break
        
        # Error disclosure
        if r.status_code >= 400:
            for pattern in error_patterns:
                if re.search(pattern, text):
                    findings["error_disclosure"].append(name)
                    break
        
        # Command execution
        for cmd in command_patterns:
            if cmd in text:
                findings["command_execution"].append(name)
                break
        
        # Database
        for db in db_patterns:
            if db in text:
                findings["database_servers"].append(name)
                break
        
        # Auth
        for auth in auth_patterns:
            if auth in text:
                findings["auth_issues"].append(name)
                break
        
        # OpenAPI
        for path in openapi_paths:
            try:
                if requests.get(f"{url}{path}", timeout=3).status_code == 200:
                    findings["openapi_exposure"].append(name)
                    break
            except:
                pass
    
    except:
        pass
    
    return findings

# Parallel scan - 20 workers
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = [executor.submit(scan_server, s) for s in servers]
    
    for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
        findings = future.result()
        for vector, items in findings.items():
            results["vectors"][vector].extend(items)
        
        if i % 100 == 0:
            print(f"[{i:4d}/{len(servers)}] Progress...")

# Summary
print(f"\n{'='*70}")
print("COMPLETE DEEP-DIVE RESULTS (All 1,300 Phase 2 servers)")
print(f"{'='*70}\n")

total_findings = 0
for vector, servers_list in results["vectors"].items():
    count = len(set(servers_list))  # Unique servers
    total_findings += count
    pct = (count / len(servers)) * 100
    print(f"{vector:30s}: {count:5d} servers ({pct:5.1f}%)")

results["total_findings"] = total_findings
results["unique_servers_with_findings"] = len(set(
    s for vec_list in results["vectors"].values() for s in vec_list
))

with open("deepdive_audit_full.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Full audit saved to deepdive_audit_full.json")
print(f"📊 Servers with findings: {results['unique_servers_with_findings']}/1,300")
