#!/usr/bin/env python3
"""Test preflight response from MCP server"""
import json
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError

def test_mcp_preflight(target_url):
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    }
    
    req = Request(target_url, method="POST")
    req.add_header("User-Agent", "mcp-authscan/1.0.0")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    req.data = json.dumps(init_payload).encode()
    
    try:
        with urlopen(req, timeout=5) as resp:
            status = resp.status
            body = resp.read(500).decode(errors='ignore')
            print(f"HTTP {status}")
            print(f"Body: {body[:200]}")
            
            if status in [200, 201, 202]:
                if 'jsonrpc' in body or '{' in body:
                    print("✓ Would PASS: JSON-RPC response")
            elif status in [400, 405, 406]:
                if 'jsonrpc' in body or '{' in body:
                    print("✓ Would PASS: JSON-RPC error response")
    except HTTPError as e:
        status = e.code
        body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
        print(f"HTTP {status}")
        print(f"Body: {body[:200]}")
        
        if status == 401:
            www_auth = e.headers.get("www-authenticate", "")
            print(f"WWW-Authenticate: {www_auth[:100]}")
            print("✓ Would PASS: OAuth challenge (401)")
        elif status in [400, 405, 406]:
            if 'jsonrpc' in body or '{' in body:
                print("✓ Would PASS: JSON-RPC error response")
            else:
                print("✗ Would FAIL: No JSON-RPC body")
        else:
            print(f"✗ Would FAIL: Unexpected status")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://api.meant.run/mcp"
    test_mcp_preflight(target)
