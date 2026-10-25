#!/usr/bin/env python3
"""
Scan servers from official MCP Registry API
"""
import requests
import json
from scanner import MCPScanner
from report import SecurityReport

def fetch_registry():
    """Pull servers from official MCP Registry"""
    try:
        resp = requests.get("https://registry.modelcontextprotocol.io/servers")
        return resp.json()
    except Exception as e:
        print(f"Registry fetch failed: {e}")
        return []

def scan_registry_servers():
    """Scan all public MCP servers from registry"""
    servers = fetch_registry()
    report = SecurityReport()
    
    for server in servers:
        name = server.get("name")
        url = server.get("baseUrl")
        
        if not url:
            continue
            
        print(f"Scanning {name} ({url})...")
        scanner = MCPScanner(url)
        findings = scanner.scan()
        report.add_findings(name, findings)
    
    return report

if __name__ == "__main__":
    report = scan_registry_servers()
    print(report.to_text())
    with open("registry_scan_results.json", "w") as f:
        json.dump(report.to_dict(), f, indent=2)
