import json
from datetime import datetime

# Load both scans
with open("final_scan_v2.json") as f:
    phase1 = json.load(f)

with open("final_scan_phase2.json") as f:
    phase2 = json.load(f)

print(f"Phase 1: {phase1['total']} servers")
print(f"Phase 2: {phase2['total']} servers")

# Merge findings
merged_findings = {}
merged_findings.update(phase1.get("findings", {}))
merged_findings.update(phase2.get("findings", {}))

# VATA 7-category scoring
# Categories: TLS/HTTPS, Input Validation, Info Disclosure, Rate Limiting, 
#             Tool Output Safety, Resource Isolation, Known Vulnerabilities
# Score: 0-12 (0-2 per category)

def vata_score(findings_list):
    """Convert findings to VATA score (0-12)"""
    score = 0
    has_info_disc = False
    has_medium = False
    
    for finding in findings_list:
        severity = finding.get("severity", "").upper()
        issue = finding.get("issue", "").lower()
        
        if severity == "HIGH":
            score += 2  # CORS or major issue
        elif severity == "MEDIUM":
            score += 1  # Rate limiting or moderate
            has_medium = True
        elif severity == "LOW":
            if "header" in issue or "powered" in issue:
                has_info_disc = True
    
    return min(score + (1 if has_info_disc else 0), 12)

# Calculate scores
total_servers = phase1['total'] + phase2['total']
critical_count = 0
high_count = 0
medium_count = 0
low_count = 0

scored_servers = []
for name, findings in merged_findings.items():
    score = vata_score(findings)
    if score >= 10:
        risk = "CRITICAL"
        critical_count += 1
    elif score >= 7:
        risk = "HIGH"
        high_count += 1
    elif score >= 4:
        risk = "MEDIUM"
        medium_count += 1
    else:
        risk = "LOW"
        low_count += 1
    
    scored_servers.append({
        "name": name,
        "vata_score": score,
        "risk": risk,
        "findings_count": len(findings)
    })

# Overall stats
secure = total_servers - len(merged_findings)
overall_score = round((secure / total_servers) * 100, 1)

result = {
    "timestamp": datetime.now().isoformat(),
    "combined_audit": "Phase1 + Phase2",
    "total": total_servers,
    "scanned": total_servers,
    "critical": critical_count,
    "high": high_count,
    "medium": medium_count,
    "low": low_count,
    "secure": secure,
    "score": overall_score,
    "findings": merged_findings,
    "scored_servers": scored_servers
}

with open("combined_vata_audit.json", "w") as f:
    json.dump(result, f, indent=2)

print(f"\n📊 Combined Results:")
print(f"  Total: {total_servers}")
print(f"  CRITICAL: {critical_count}")
print(f"  HIGH: {high_count}")
print(f"  MEDIUM: {medium_count}")
print(f"  LOW: {low_count}")
print(f"  Secure: {secure}")
print(f"  Overall Score: {overall_score}%")
print(f"\n✅ Saved to combined_vata_audit.json")
