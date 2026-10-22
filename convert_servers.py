import json

servers = []
with open("/home/lhmisme/vata/mcp-authscan/mcp_servers_to_scan.json", "r") as f:
    for line in f:
        line = line.strip()
        if line and not line.startswith("#"):
            servers.append({"url": line})

with open("mcp_servers.json", "w") as f:
    json.dump(servers, f, indent=2)

print(f"Converted {len(servers)} servers to JSON")
