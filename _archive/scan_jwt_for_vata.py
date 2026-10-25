#!/usr/bin/env python3
import json
import asyncio
from jwt_weakness.detector import JWTWeaknessDetector

async def scan_servers(servers_file="mcp_servers.json", output_file="vata_jwt_findings.json"):
    """Load servers and scan for JWT weaknesses."""
    
    with open(servers_file, 'r') as f:
        servers = json.load(f)
    
    findings = {
        "scan_date": "2026-10-22T06:01:00Z",
        "total_servers": len(servers),
        "vulnerable": [],
        "safe": [],
        "errors": [],
        "scanned": 0
    }
    
    for i, server in enumerate(servers, 1):
        url = server.get("url") or server.get("endpoint") or server.get("server_url")
        if not url:
            continue
        
        findings["scanned"] += 1
        
        if i % 500 == 0:
            print(f"[{i}/{len(servers)}] Scanned {findings['scanned']} servers, found {len(findings['vulnerable'])} vulnerable", flush=True)
        
        try:
            detector = JWTWeaknessDetector(url, timeout=2)
            results = detector.run()
            
            if results:
                findings["vulnerable"].append({"server": url, "findings": results})
            else:
                findings["safe"].append(url)
        
        except Exception as e:
            findings["errors"].append({"server": url, "error": type(e).__name__})
    
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2)
    
    print(f"\n✅ Scan complete: {output_file}")
    print(f"   Scanned: {findings['scanned']}/{findings['total_servers']}")
    print(f"   Vulnerable: {len(findings['vulnerable'])}")
    print(f"   Safe: {len(findings['safe'])}")
    print(f"   Errors: {len(findings['errors'])}")
    
    if findings["vulnerable"]:
        print(f"\n🔴 VULNERABLE SERVERS:")
        for v in findings["vulnerable"][:5]:
            print(f"   - {v['server']}")

if __name__ == "__main__":
    asyncio.run(scan_servers())
