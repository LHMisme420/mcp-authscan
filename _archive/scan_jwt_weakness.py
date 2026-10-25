#!/usr/bin/env python3
"""
Scan 700+ MCP servers for JWT weakness vulnerabilities
"""
import json
import asyncio
from pathlib import Path
from jwt_weakness.detector import JWTWeaknessDetector

async def scan_servers(servers_file="mcp_servers.json", output_file="jwt_findings.json"):
    """Load servers and scan for JWT weaknesses."""
    
    with open(servers_file, 'r') as f:
        servers = json.load(f)
    
    findings = {
        "scan_date": "2026-10-22",
        "total_servers": len(servers),
        "vulnerable": [],
        "safe": [],
        "errors": []
    }
    
    for i, server in enumerate(servers, 1):
        url = server.get("url") or server.get("endpoint")
        print(f"[{i}/{len(servers)}] Scanning {url}...", end=" ")
        
        try:
            detector = JWTWeaknessDetector(url, timeout=5)
            results = detector.run()
            
            if results:
                findings["vulnerable"].append({
                    "server": url,
                    "findings": results
                })
                print("❌ VULNERABLE")
            else:
                findings["safe"].append(url)
                print("✅ safe")
        
        except Exception as e:
            findings["errors"].append({"server": url, "error": str(e)})
            print(f"⚠️  error: {e}")
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2)
    
    print(f"\n📊 Results saved to {output_file}")
    print(f"   Vulnerable: {len(findings['vulnerable'])}")
    print(f"   Safe: {len(findings['safe'])}")
    print(f"   Errors: {len(findings['errors'])}")
    
    return findings

if __name__ == "__main__":
    results = asyncio.run(scan_servers())
