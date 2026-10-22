#!/usr/bin/env python3
import json
from jwt_weakness.extended_detector import ExtendedJWTDetector
from jwt_weakness.oauth_patterns import OAuthPatternDetector

with open("mcp_servers.json") as f:
    servers = json.load(f)

findings = {
    "scan_date": "2026-10-22T06:05:00Z",
    "total_servers": len(servers),
    "vulnerable_by_type": {},
    "critical_issues": [],
    "high_issues": [],
    "medium_issues": [],
    "scanned": 0
}

for i, s in enumerate(servers, 1):
    url = s.get("url")
    if not url:
        continue
    
    findings["scanned"] += 1
    
    if findings["scanned"] % 1000 == 0:
        print(f"[{findings['scanned']}/{len(servers)}] Critical: {len(findings['critical_issues'])}, High: {len(findings['high_issues'])}", flush=True)
    
    try:
        # JWT checks
        jwt_detector = ExtendedJWTDetector(url, timeout=2)
        jwt_results = jwt_detector.run()
        
        # OAuth pattern checks
        oauth_detector = OAuthPatternDetector(url, timeout=2)
        oauth_results = oauth_detector.run()
        
        all_results = jwt_results + oauth_results
        
        for result in all_results:
            severity = result.get("severity", "MEDIUM")
            if severity not in findings["vulnerable_by_type"]:
                findings["vulnerable_by_type"][severity] = []
            
            issue = {"server": url, "type": result.get("type"), "severity": severity}
            findings["vulnerable_by_type"][severity].append(issue)
            
            if severity == "CRITICAL":
                findings["critical_issues"].append(issue)
            elif severity == "HIGH":
                findings["high_issues"].append(issue)
            elif severity == "MEDIUM":
                findings["medium_issues"].append(issue)
    
    except:
        pass

with open("vata_comprehensive_findings.json", "w") as f:
    json.dump(findings, f, indent=2)

print(f"\n✅ Comprehensive scan complete")
print(f"   Scanned: {findings['scanned']}")
print(f"   CRITICAL: {len(findings['critical_issues'])}")
print(f"   HIGH: {len(findings['high_issues'])}")
print(f"   MEDIUM: {len(findings['medium_issues'])}")

if findings["critical_issues"][:5]:
    print(f"\n🔴 Sample CRITICAL issues:")
    for issue in findings["critical_issues"][:5]:
        print(f"   {issue['server']}: {issue['type']}")
