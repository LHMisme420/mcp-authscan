import requests
import re
import json

servers = []

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
    print(f"   Error: {e}")

print("\n📡 GitHub awesome-mcp-servers...")
try:
    r = requests.get("https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md", timeout=10)
    content = r.text
    pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
    matches = re.findall(pattern, content)
    
    skip_patterns = ['img.shields', '.svg', 'reddit', 'discord', 'twitter', 'badge', 'github.com/punkpeye']
    for name, url in matches:
        skip = any(re.search(p, url, re.IGNORECASE) for p in skip_patterns)
        if not skip and ('/mcp' in url.lower() or 'mcp' in name.lower()):
            servers.append({"name": name.strip(), "url": url, "source": "awesome-github"})
    print(f"   Found {len([s for s in servers if s['source']=='awesome-github'])} endpoints")
except Exception as e:
    print(f"   Error: {e}")

print("\n📡 GitHub raw search (mcp-server repos)...")
try:
    r = requests.get("https://api.github.com/search/repositories?q=topic:mcp-server&sort=stars&per_page=100", timeout=10, headers={"Accept": "application/vnd.github.v3+json"})
    data = r.json()
    for repo in data.get("items", []):
        servers.append({"name": repo['full_name'], "url": repo['clone_url'], "source": "github-topic"})
    print(f"   Found {len([s for s in servers if s['source']=='github-topic'])} repos")
except Exception as e:
    print(f"   Error: {e}")

print("\n📡 npm MCP packages...")
try:
    r = requests.get("https://registry.npmjs.org/-/v1/search?text=mcp&size=100", timeout=10)
    data = r.json()
    for pkg in data.get("objects", []):
        servers.append({"name": pkg['package']['name'], "url": pkg['package']['links']['npm'], "source": "npm"})
    print(f"   Found {len([s for s in servers if s['source']=='npm'])} packages")
except Exception as e:
    print(f"   Error: {e}")

# Deduplicate
seen = set()
unique = []
for s in servers:
    key = s.get("url") or s.get("name")
    if key and key not in seen:
        seen.add(key)
        unique.append(s)

print(f"\n✅ Total unique servers: {len(unique)}")
print("\nBreakdown:")
for source in set(s['source'] for s in unique):
    count = len([s for s in unique if s['source']==source])
    print(f"   {source:20s}: {count}")

# Save to file
with open("phase2_servers.json", "w") as f:
    json.dump(unique, f, indent=2)
print(f"\n📝 Saved to phase2_servers.json")
