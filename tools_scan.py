import sys
from mcp_authscan.surface_capture import capture_surface
url = sys.argv[1]
host = url.split("//", 1)[-1].split("/", 1)[0]
res = capture_surface(url, allow_private=False, allowed_hosts=[host])
tools = res.get("surface", {}).get("tools", []) or []
print("tools", len(tools))
print("captured", res.get("captured"))
print("reasons", res.get("reasons"))
import json
for t in tools:
    print(t.get("name"), "::", (t.get("description") or "").replace("\n", " "))
