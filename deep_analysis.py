import json
from collections import defaultdict

# Load combined audit
with open("combined_vata_audit.json") as f:
    data = json.load(f)

findings = data.get("findings", {})
scored = data.get("scored_servers", [])

print("="*70)
print("PHASE 2 DEEP ANALYSIS - MCP ECOSYSTEM POSTURE")
print("="*70)

# 1. Categorize by finding type
categories = defaultdict(list)
for server, issues in findings.items():
    for issue in issues:
        severity = issue.get("severity", "").upper()
        issue_text = issue.get("issue", "")
        
        if "CORS" in issue_text.upper():
            categories["CORS_Wildcard"].append(server)
        elif "rate" in issue_text.lower():
            categories["Rate_Limiting_Missing"].append(server)
        elif "header" in issue_text.lower():
            categories["Info_Disclosure"].append(server)
        else:
            categories["Other"].append(server)

print("\n📊 FINDING CATEGORIES:")
for category, servers in sorted(categories.items()):
    print(f"  {category:30s}: {len(servers):5d} servers")

# 2. Severity distribution
severity_dist = defaultdict(int)
for server, issues in findings.items():
    for issue in issues:
        severity = issue.get("severity", "UNKNOWN").upper()
        severity_dist[severity] += 1

print("\n⚠️  SEVERITY DISTRIBUTION:")
for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    count = severity_dist.get(severity, 0)
    print(f"  {severity:10s}: {count:5d} findings")

# 3. Risk tier breakdown
risk_tiers = defaultdict(int)
for server in scored:
    risk_tiers[server['risk']] += 1

print("\n🎯 RISK TIER BREAKDOWN:")
for risk in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    count = risk_tiers.get(risk, 0)
    pct = (count / data['total']) * 100
    print(f"  {risk:10s}: {count:5d} servers ({pct:5.1f}%)")

# 4. Top concerns
print("\n🔴 TOP SECURITY CONCERNS:")
print(f"  1. Rate Limiting: {len(categories.get('Rate_Limiting_Missing', []))} servers")
print(f"     → Agent DoS vulnerability across {(len(categories.get('Rate_Limiting_Missing', []))/data['total']*100):.1f}% of ecosystem")
print(f"\n  2. Info Disclosure: {len(categories.get('Info_Disclosure', []))} servers")
print(f"     → Server version/framework fingerprinting enabled")
print(f"\n  3. CORS Misconfiguration: {len(categories.get('CORS_Wildcard', []))} servers")
print(f"     → Cross-origin access allowed")

# 5. Secure servers (good baseline)
secure = data.get('secure', 0)
print(f"\n✅ SECURE BASELINE: {secure} servers (0 findings)")

print("\n" + "="*70)
print(f"ECOSYSTEM SCORE: {data['score']}%")
print(f"PRIMARY VECTOR: Rate Limiting DoS (Agent throttling bypass)")
print("="*70)
