#!/usr/bin/env python3
"""Send proper MCP initialize POST to discover OAuth."""
import sys
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

if len(sys.argv) < 2:
    print("Usage: python3 mcp_init.py <mcp_url>")
    sys.exit(1)

url = sys.argv[1]
print(f"\n[*] MCP OAuth Discovery")
print(f"[*] Target: {url}\n")

# RFC 9728 MCP initialize request (unauthenticated)
init_payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {
            "name": "mcp-authscan",
            "version": "1.0.0"
        }
    }
}

req = Request(url, method="POST")
req.add_header("Content-Type", "application/json")
req.add_header("Accept", "application/json, text/event-stream")
req.data = json.dumps(init_payload).encode()

try:
    with urlopen(req, timeout=5) as resp:
        status = resp.status
        print(f"[✓] HTTP {status}")
        
        if status == 200:
            print(f"[!] ENDPOINT ACCEPTS UNAUTHENTICATED REQUESTS (VULNERABILITY)")
            body = resp.read(1000).decode(errors='ignore')
            print(f"\nResponse preview:\n{body}\n")
            
        elif status == 401:
            print(f"[*] Server requires authentication")
            print(f"\nResponse headers:")
            for header, value in resp.headers.items():
                if header.lower() in ['www-authenticate', 'authorization', 'content-type']:
                    print(f"  {header}: {value}")
            print()
            
except HTTPError as e:
    status = e.code
    print(f"[!] HTTP {status}")
    
    if status == 401:
        print(f"[*] Server requires authentication")
        print(f"\nResponse headers:")
        for header, value in e.headers.items():
            if header.lower() in ['www-authenticate', 'authorization', 'content-type']:
                print(f"  {header}: {value}")
        print()
        
    elif status in [200, 201, 202]:
        print(f"[!] ENDPOINT ACCEPTS UNAUTHENTICATED REQUESTS (VULNERABILITY)")
        if e.fp:
            body = e.fp.read(1000).decode(errors='ignore')
            print(f"\nResponse preview:\n{body}\n")
            
    else:
        print(f"[?] Unexpected status")

