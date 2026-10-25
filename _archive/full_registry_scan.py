#!/usr/bin/env python3
"""Full MCP Official Registry scan"""
import requests
import json
from scanner import MCPScanner
from report import SecurityReport
from datetime import datetime

def get_all_servers():
    """Get all servers from official registry"""
    all_servers = []
    
    try:
        print("🔍 Fetching full official registry...")
        r = requests.get("https://registry.modelcontextprotocol.io/v0.1/servers", timeout=10)
        data = r.json()
        
        for item in data.get("servers", []):
            server = item.get("server", {})
            name = server.get("name", "unknown")
            
            for remote in server.get("remotes", []):
                if remote.get("type") == "streamable-http":
                    url = remote.get("url")
                    all_servers.append({"name": name, "url": url})
        
        print(f"✅ Found {len(all_servers)} endpoints\n")
    except Exception as e:
        print(f"❌ ERROR: {e}")
    
    return all_servers

def scan_all():
    servers = get_all_servers()
    
    report = SecurityReport()
    critical_count = 0
    high_count = 0
    clean_count = 0
    
    print(f"Scanning {len(servers)} endpoints...\n")
    print("-" * 60)
    
    for i, server in enumerate(servers, 1):
        url = server.get("url")
        name = server.get("name")
        
        try:
            scanner = MCPScanner(url)
            findings = scanner.scan()
            
            if findings:
                critical = len([f for f in findings if f.get("severity") == "CRITICAL"])
                high = len([f for f in findings if f.get("severity") == "HIGH"])
                
                critical_count += critical
                high_count += high
                
                status = "⚠️  FINDINGS"
                print(f"[{i:3d}] {name:40s} {status} ({critical}C {high}H)")
                
            else:
                clean_count += 1
                print(f"[{i:3d}] {name:40s} ✅ CLEAN")
            
            report.add_findings(name, findings)
            
        except Exception as e:
            print(f"[{i:3d}] {name:40s} ❌ ERROR")
    
    print("-" * 60)
    return report, critical_count, high_count, clean_count

if __name__ == "__main__":
    report, critical, high, clean = scan_all()
    
    print(f"\n{'='*60}")
    print(f"📊 FULL REGISTRY SCAN RESULTS")
    print(f"{'='*60}")
    print(f"Total Endpoints:    {len(report.findings)}")
    print(f"CRITICAL Findings:  {critical}")
    print(f"HIGH Findings:      {high}")
    print(f"Clean Servers:      {clean}")
    print(f"Security Score:     {100 * clean // len(report.findings)}%")
    print(f"{'='*60}\n")
    
    # Save detailed results
    results = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "full_registry",
        "source": "registry.modelcontextprotocol.io",
        "total_endpoints": len(report.findings),
        "critical_findings": critical,
        "high_findings": high,
        "clean_servers": clean,
        "security_score_percent": 100 * clean // len(report.findings),
        "findings": report.to_dict()
    }
    
    with open("full_registry_scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("💾 Results saved to full_registry_scan_results.json\n")
    
    # Show findings summary
    if critical > 0 or high > 0:
        print("Findings by severity:")
        for server, findings in report.to_dict().items():
            if findings:
                for f in findings:
                    sev = f.get("severity")
                    print(f"  [{sev}] {server}: {f.get('issue')}")
