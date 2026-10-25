#!/usr/bin/env python3
import json
from jwt_weakness.extended_detector import ExtendedJWTDetector

with open("mcp_servers.json") as f:
    servers = json.load(f)

findings = {"vulnerable": [], "safe": 0, "total": len(servers)}

for i, s in enumerate(servers, 1):
    if i % 1000 == 0:
        print(f"[{i}/{len(servers)}] vulnerable: {len(findings['vulnerable'])}", flush=True)
    
    try:
        d = ExtendedJWTDetector(s["url"], timeout=2)
        r = d.run()
        if r:
            findings["vulnerable"].append({"server": s["url"], "issues": r})
        else:
            findings["safe"] += 1
    except:
        pass

with open("vata_jwt_expanded.json", "w") as f:
    json.dump(findings, f, indent=2)

print(f"\n✅ Done: {len(findings['vulnerable'])} vulnerable, {findings['safe']} safe")
