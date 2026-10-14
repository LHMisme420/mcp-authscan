#!/usr/bin/env python3
"""Comprehensive MCP server discovery and scanning"""
import requests
import json
import re
from scanner import MCPScanner
from report import SecurityReport
from datetime import datetime

def discover_servers():
    """Discover MCP servers from multiple sources"""
    servers = []
    
    # Source 1: Official Registry
    print("📡 Official Registry...")
    try:
        r = requests.get("https://registry.modelcontextprotocol.io/v0.1/servers", timeout=10)
        data = r.json()
        for item in data.get("servers", []):
            server = item.get("server", {})
            name = server.get("name", "unknown")
            for remote in server.get("remotes", []):
                if remote.get("type") == "streamable-http":
                    url = remote.get("url")
                    servers.append({"name": name, "url": url, "source": "official"})
        print(f"   Found {len([s for s in servers if s['source']=='official'])} endpoints")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    # Source 2: GitHub awesome-mcp-servers (direct URLs only)
    print("📡 GitHub awesome-mcp-servers...")
    try:
        r = requests.get("https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md", timeout=10)
        content = r.text
        
        # Extract [name](url) patterns
        pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
        matches = re.findall(pattern, content)
        
        # Filter for real server URLs (exclude badges, social media, etc)
        skip_patterns = ['img.shields', '.svg', 'reddit', 'discord', 'twitter', 'github.com/.*issues', 'badge']
        
        for name, url in matches:
            skip = False
            for pattern in skip_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    skip = True
                    break
            
            if not skip and '/mcp' in url.lower():
                # Only add if looks like actual server endpoint
                servers.append({"name": name.strip(), "url": url, "source": "github"})
        
        github_count = len([s for s in servers if s['source']=='github'])
        print(f"   Found {github_count} endpoints")
    except Exception as e:
        print(f"   ERROR: {e}")
    
    # Deduplicate
    seen = set()
    unique = []
    for s in servers:
        key = s.get("url")
        if key and key not in seen:
            seen.add(key)
            unique.append(s)
    
    return unique

def scan_all(servers):
    """Scan all discovered servers"""
    report = SecurityReport()
    
    critical = 0
    high = 0
    clean = 0
    errors = 0
    
    print(f"\n🔍 Scanning {len(servers)} servers...\n")
    print("-" * 70)
    
    for i, server in enumerate(servers, 1):
        url = server.get("url")
        name = server.get("name")
        source = server.get("source")
        
        try:
            scanner = MCPScanner(url)
            findings = scanner.scan()
            
            c = len([f for f in findings if f.get("severity") == "CRITICAL"])
            h = len([f for f in findings if f.get("severity") == "HIGH"])
            
            critical += c
            high += h
            
            if findings:
                status = f"⚠️  {c}C {h}H"
            else:
                status = "✅"
                clean += 1
            
            print(f"[{i:3d}] {source:8s} {name:40s} {status}")
            report.add_findings(f"{name} ({source})", findings)
            
        except:
            errors += 1
            print(f"[{i:3d}] {source:8s} {name:40s} ❌")
    
    print("-" * 70)
    
    return report, critical, high, clean, errors

if __name__ == "__main__":
    servers = discover_servers()
    report, critical, high, clean, errors = scan_all(servers)
    
    total = len(servers)
    score = 100 * clean // total if total > 0 else 0
    
    print(f"\n{'='*70}")
    print(f"📊 COMPREHENSIVE MCP REGISTRY SCAN")
    print(f"{'='*70}")
    print(f"Total Servers:      {total}")
    print(f"CRITICAL Findings:  {critical}")
    print(f"HIGH Findings:      {high}")
    print(f"Clean Servers:      {clean}")
    print(f"Scan Errors:        {errors}")
    print(f"Security Score:     {score}%")
    print(f"{'='*70}\n")
    
    # Save results
    results = {
        "timestamp": datetime.now().isoformat(),
        "scan_type": "comprehensive_multi_source",
        "sources": ["official_registry", "github_awesome"],
        "total_servers": total,
        "critical_findings": critical,
        "high_findings": high,
        "clean_servers": clean,
        "errors": errors,
        "security_score": score,
        "findings": report.to_dict()
    }
    
    with open("comprehensive_scan_results.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print("💾 Results saved to comprehensive_scan_results.json")
    
    # Show findings
    if critical > 0 or high > 0:
        print("\n🚨 Findings:")
        for server, findings in report.to_dict().items():
            if findings:
                for f in findings:
                    print(f"  [{f.get('severity')}] {server}: {f.get('issue')}")
