import requests
import re

servers = []

print("📡 Official Registry...")
r = requests.get("https://registry.modelcontextprotocol.io/v0.1/servers", timeout=10)
data = r.json()
for item in data.get("servers", []):
    server = item.get("server", {})
    name = server.get("name", "unknown")
    for remote in server.get("remotes", []):
        if remote.get("type") == "streamable-http":
            url = remote.get("url")
            servers.append({"name": name, "url": url, "source": "official"})

print(f"   Found {len(servers)} endpoints\n")

print("📡 GitHub awesome-mcp-servers...")
r = requests.get("https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md", timeout=10)
content = r.text
pattern = r'\[([^\]]+)\]\((https?://[^)]+)\)'
matches = re.findall(pattern, content)

skip_patterns = ['img.shields', '.svg', 'reddit', 'discord', 'twitter', 'badge']
for name, url in matches:
    skip = any(re.search(p, url, re.IGNORECASE) for p in skip_patterns)
    if not skip and '/mcp' in url.lower():
        servers.append({"name": name.strip(), "url": url, "source": "github"})

github_count = len([s for s in servers if s['source']=='github'])
print(f"   Found {github_count} endpoints\n")

seen = set()
unique = []
for s in servers:
    key = s.get("url")
    if key and key not in seen:
        seen.add(key)
        unique.append(s)

print(f"✅ Total unique: {len(unique)} servers\n")
print("First 10:")
for s in unique[:10]:
    print(f"  {s['source']:8s} {s['name']:40s} {s['url']}")
