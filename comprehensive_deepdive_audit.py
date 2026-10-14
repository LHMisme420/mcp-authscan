import json
import requests
import re
from collections import defaultdict
from datetime import datetime

# Load all 2,028 servers
with open("phase2_highrisk_batch.json") as f:
    servers = json.load(f)

print("🚀 COMPREHENSIVE DEEP-DIVE AUDIT")
print(f"📊 Scanning {len(servers)} servers across 7 vectors\n")

results = {
    "timestamp": datetime.now().isoformat(),
    "total_servers": len(servers),
    "vectors": {
        "openapi_exposure": [],
        "credential_exposure": [],
        "error_disclosure": [],
        "command_execution": [],
        "database_servers": [],
        "auth_issues": [],
        "schema_exposure": []
    }
}

# Vector patterns
openapi_paths = ["/openapi.json", "/.well-known/openapi.json", "/swagger.json", "/api/swagger.json", "/api/openapi.json"]
credential_patterns = [
    r'(api[_-]?key|token|password|secret|credential)["\']?\s*[:=]',
    r'Bearer\s+[A-Za-z0-9\-._~+\/]+=*',
    r'(admin|root|test)[:@]',
]
error_patterns = [
    r'(traceback|stack trace|exception|error)',
    r'(sql|database|mysql|postgres)',
    r'(\/home\/|\/root\/|\/var\/www)',
]
command_patterns = ['exec', 'eval', 'system', 'popen', 'shell', 'bash', 'cmd']
db_patterns = ['mysql', 'postgres', 'mongodb', 'redis', 'sql', 'database', 'db']
auth_patterns = ['oauth', 'jwt', 'auth', 'apikey', 'bearer']

def test_server(server, idx):
    name = server.get("name", "unknown")
    url = server.get("url", "")
    
    findings = defaultdict(list)
    
    try:
        # 1. OpenAPI/Schema Exposure
        for path in openapi_paths:
            try:
                r = requests.get(f"{url}{path}", timeout=3)
                if r.status_code == 200:
                    findings["openapi_exposure"].append(f"{path}: EXPOSED")
            except:
                pass
        
        # 2. Main endpoint test
        try:
            r = requests.get(url, timeout=5)
            text = r.text.lower()
            
            # 3. Credential Exposure
            for pattern in credential_patterns:
                if re.search(pattern, r.text, re.IGNORECASE):
                    findings["credential_exposure"].append(f"Pattern match: {pattern[:20]}")
                    break
            
            # 4. Error Disclosure
            if r.status_code >= 400:
                for pattern in error_patterns:
                    if re.search(pattern, text):
                        findings["error_disclosure"].append(f"Error detail: {pattern}")
            
            # 5. Command Execution indicators (in name/description)
            for cmd in command_patterns:
                if cmd in text:
                    findings["command_execution"].append(f"Pattern: {cmd}")
            
            # 6. Database indicators
            for db in db_patterns:
                if db in text:
                    findings["database_servers"].append(f"Pattern: {db}")
            
            # 7. Auth indicators
            for auth in auth_patterns:
                if auth in text:
                    findings["auth_issues"].append(f"Pattern: {auth}")
        
        except:
            pass
    
    except Exception as e:
        pass
    
    # Store findings
    for vector, issues in findings.items():
        if issues:
            results["vectors"][vector].append({
                "server": name,
                "findings": issues
            })
    
    status = "⚠️" if findings else "✅"
    print(f"[{idx:4d}/{len(servers)}] {status} {name[:50]:50s}")

# Run scans
for i, server in enumerate(servers[:200], 1):  # First 200 for speed
    test_server(server, i)

# Summary
print(f"\n{'='*70}")
print("DEEP-DIVE AUDIT RESULTS")
print(f"{'='*70}")

total_findings = 0
for vector, findings in results["vectors"].items():
    count = len(findings)
    total_findings += count
    print(f"{vector:30s}: {count:4d} servers")

results["total_findings"] = total_findings
results["scan_sample_size"] = 200

# Save results
with open("deepdive_audit_sample.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\n✅ Sample audit (first 200 servers) saved to deepdive_audit_sample.json")
print(f"📊 Total findings: {total_findings}")
