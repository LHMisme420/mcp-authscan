#!/usr/bin/env python3
"""ULTIMATE MCP SECURITY SCANNER - 25+ vulnerability checks"""
import json
from jwt_weakness.extended_detector import ExtendedJWTDetector
from jwt_weakness.oauth_patterns import OAuthPatternDetector
from jwt_weakness.mcp_security_scanner import MCPSecurityScanner
from jwt_weakness.advanced_checks import AdvancedSecurityChecks

with open("mcp_servers.json") as f:
    servers = json.load(f)

findings = {
    "scanner": "ULTIMATE MCP SECURITY SCANNER v1.0",
    "checks": 25,
    "total_servers": len(servers),
    "critical": 0,
    "high": 0,
    "medium": 0,
    "vulnerable_servers": []
}

for i, s in enumerate(servers, 1):
    url = s.get("url")
    if not url:
        continue
    
    if i % 1000 == 0:
        print(f"[{i}] CRITICAL: {findings['critical']}, HIGH: {findings['high']}", flush=True)
    
    try:
        # Run all 4 detector suites
        jwt_r = ExtendedJWTDetector(url, timeout=2).run()
        oauth_r = OAuthPatternDetector(url, timeout=2).run()
        mcp_r = MCPSecurityScanner(url, timeout=2).run()
        adv_r = AdvancedSecurityChecks(url, timeout=2).run()
        
        all_results = jwt_r + oauth_r + mcp_r + adv_r
        
        if all_results:
            findings["vulnerable_servers"].append({
                "server": url,
                "issues": len(all_results),
                "critical": len([x for x in all_results if x.get("severity") == "CRITICAL"])
            })
        
        for result in all_results:
            sev = result.get("severity", "MEDIUM")
            if sev == "CRITICAL":
                findings["critical"] += 1
            elif sev == "HIGH":
                findings["high"] += 1
            else:
                findings["medium"] += 1
    except:
        pass

with open("vata_ultimate_findings.json", "w") as f:
    json.dump(findings, f, indent=2)

print(f"\n🔥 ULTIMATE SCANNER RESULTS")
print(f"   Servers: {len(servers)}")
print(f"   Checks: 25+")
print(f"   CRITICAL: {findings['critical']}")
print(f"   HIGH: {findings['high']}")
print(f"   MEDIUM: {findings['medium']}")
print(f"   Vulnerable: {len(findings['vulnerable_servers'])}")
