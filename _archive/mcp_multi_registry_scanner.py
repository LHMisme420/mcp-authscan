#!/usr/bin/env python3
"""
Scan from multiple MCP registries and directories
- Official: registry.modelcontextprotocol.io
- Glama: glama.ai/mcp
- PulseMCP: pulsemcp.com
- mcp.so: mcp.so
- GitHub: Community indexes
"""
import requests
import json
from scanner import MCPScanner
from report import SecurityReport

REGISTRIES = {
    "official": {
        "url": "https://registry.modelcontextprotocol.io/servers",
        "parser": lambda r: r.json() if isinstance(r.json(), list) else r.json().get("servers", [])
    },
    "glama": {
        "url": "https://glama.ai/api/mcp-servers",
        "parser": lambda r: r.json().get("data", [])
    },
    "pulsemcp": {
        "url": "https://pulsemcp.com/api/servers",
        "parser": lambda r: r.json().get("servers", [])
    },
    "mcp_so": {
        "url": "https://mcp.so/api/servers",
        "parser": lambda r: r.json().get("results", [])
    },
    "github_awesome": {
        "url": "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md",
        "parser": "markdown_links"  # Manual parsing of markdown links
    }
}

def fetch_from_registry(name, config):
    """Fetch servers from a registry"""
    try:
        print(f"  Fetching from {name}...")
        resp = requests.get(config["url"], timeout=10)
        resp.raise_for_status()
        
        if config["parser"] == "markdown_links":
            # Parse markdown for links
            servers = parse_markdown_links(resp.text)
        else:
            servers = config["parser"](resp)
        
        print(f"  Found {len(servers)} servers")
        return servers
    except Exception as e:
        print(f"  ERROR fetching {name}: {e}")
        return []

def parse_markdown_links(content):
    """Extract MCP server URLs from markdown"""
    import re
    # Match: [name](url)
    pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
    matches = re.findall(pattern, content)
    return [{"name": name, "url": url} for name, url in matches if "/mcp" in url.lower()]

def scan_all_registries():
    """Scan servers from all registries"""
    all_servers = {}
    
    print("🔍 Fetching from all MCP registries...\n")
    
    for name, config in REGISTRIES.items():
        servers = fetch_from_registry(name, config)
        all_servers[name] = servers
    
    # Deduplicate by URL
    seen_urls = set()
    unique_servers = []
    
    for registry_name, servers in all_servers.items():
        for server in servers:
            url = server.get("url") or server.get("baseUrl") or server.get("endpoint")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_servers.append({
                    "name": server.get("name"),
                    "url": url,
                    "registry": registry_name
                })
    
    print(f"\n✅ Total unique servers across all registries: {len(unique_servers)}\n")
    
    # Scan all servers
    report = SecurityReport()
    
    for i, server in enumerate(unique_servers, 1):
        name = server.get("name", "unknown")
        url = server.get("url")
        registry = server.get("registry")
        
        print(f"[{i}/{len(unique_servers)}] Scanning {name} ({registry}) @ {url}")
        
        try:
            scanner = MCPScanner(url)
            findings = scanner.scan()
            report.add_findings(name, findings)
        except Exception as e:
            print(f"  ERROR: {e}")
    
    return report

if __name__ == "__main__":
    report = scan_all_registries()
    
    print("\n" + "="*60)
    print(report.to_text())
    print("="*60)
    
    # Save results
    with open("multi_registry_scan_results.json", "w") as f:
        json.dump({
            "timestamp": str(datetime.datetime.now()),
            "total_servers_scanned": len(report.findings),
            "findings": report.to_dict()
        }, f, indent=2)
    
    print(f"\n💾 Results saved to multi_registry_scan_results.json")
