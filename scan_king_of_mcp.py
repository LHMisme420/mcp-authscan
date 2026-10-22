#!/usr/bin/env python3
"""KING OF MCP DETECTION - Full vulnerability scan"""
import json
from jwt_weakness.mcp_security_scanner import MCPSecurityScanner

with open("mcp_servers.json") as f:
    servers = json.load(f)

findings = {
    "name": "KING OF MCP DETECTION",
    "scan_date": "2026-10-22T06:07:00Z",
    "total_servers": len(servers),
    "vulnerability_count": {},
    "critical_servers": [],
    "summary": {}
}

for i, s in enumerate(servers, 1):
    url = s.get("url")
    if not url:
        continue
    
    if i % 1000 == 0:
        print(f"[{i}/{len(servers)}] Critical servers: {len(findings['critical_servers'])}", flush=True)
    
    try:
        scanner = MCPSecurityScanner(url, timeout=2)
        results = scanner.run()
        
        for result in results:
            vuln_type = result.get("type")
            severity = result.get("severity", "MEDIUM")
            
            if vuln_type not in findings["vulnerability_count"]:
                findings["vulnerability_count"][vuln_type] = {"total": 0, "critical": 0}
            
            findings["vulnerability_count"][vuln_type]["total"] += 1
            
            if severity == "CRITICAL":
                findings["vulnerability_count"][vuln_type]["critical"] += 1
                if len(findings["critical_servers"]) < 100:
                    findings["critical_servers"].append({
                        "server": url,
                        "vuln_type": vuln_type
                    })
    except:
        pass

with open("vata_king_of_mcp.json", "w") as f:
    json.dump(findings, f, indent=2)

# Summary
critical_vulns = sum(v.get("critical", 0) for v in findings["vulnerability_count"].values())
total_vulns = sum(v.get("total", 0) for v in findings["vulnerability_count"].values())

print(f"\n👑 KING OF MCP DETECTION - RESULTS")
print(f"   Servers scanned: {len(servers)}")
print(f"   Vulnerabilities found: {total_vulns}")
print(f"   CRITICAL: {critical_vulns}")
print(f"   Vulnerability types: {len(findings['vulnerability_count'])}")

if findings["vulnerability_count"]:
    print(f"\n🔴 TOP FINDINGS:")
    for vuln, counts in sorted(findings["vulnerability_count"].items(), 
                               key=lambda x: x[1]["critical"], reverse=True)[:5]:
        print(f"   {vuln}: {counts['total']} ({counts['critical']} critical)")
