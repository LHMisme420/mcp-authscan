#!/usr/bin/env python3
import requests
import json
from scanner import MCPScanner
from report import SecurityReport

def get_servers():
    all_servers = []
    
    try:
        print("Fetching from official registry...")
        r = requests.get("https://registry.modelcontextprotocol.io/v0.1/servers", timeout=10)
        data = r.json()
        
        for item in data.get("servers", []):
            server = item.get("server", {})
            name = server.get("name", "unknown")
            
            for remote in server.get("remotes", []):
                if remote.get("type") == "streamable-http":
                    url = remote.get("url")
                    all_servers.append({"name": name, "url": url})
        
        print(f"  Got {len(all_servers)} server endpoints")
    except Exception as e:
        print(f"  ERROR: {e}")
    
    return all_servers

def scan():
    servers = get_servers()
    print(f"\nScanning {len(servers)} endpoints...\n")
    
    report = SecurityReport()
    critical_count = 0
    
    for i, server in enumerate(servers[:10], 1):
        url = server.get("url")
        name = server.get("name")
        
        print(f"[{i}] {name} @ {url}")
        
        try:
            scanner = MCPScanner(url)
            findings = scanner.scan()
            if findings:
                critical_count += len([f for f in findings if f.get("severity") == "CRITICAL"])
                for f in findings:
                    print(f"    [{f['severity']}] {f['issue']}")
            else:
                print(f"    ✅ Clean")
            report.add_findings(name, findings)
        except Exception as e:
            print(f"    ❌ Error: {e}")
    
    return report, critical_count

if __name__ == "__main__":
    report, critical = scan()
    print("\n" + "="*60)
    print(f"✅ SCAN COMPLETE: {critical} CRITICAL findings found")
    print("="*60)
