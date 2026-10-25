#!/usr/bin/env python3
"""RFC 9728 MCP → RFC 8414 OAuth discovery chain."""
import json
import sys
import re
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import socket

USER_AGENT = "mcp-authscan/1.0.0"

def discover_oauth(mcp_server_url):
    """Discover OAuth endpoints from MCP server using RFC 9728 → RFC 8414 chain."""
    base = mcp_server_url.rstrip("/")
    
    print(f"[*] MCP → OAuth Discovery", file=sys.stderr)
    print(f"[*] Target: {base}\n", file=sys.stderr)
    
    # Step 1: POST MCP initialize (unauthenticated)
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-authscan", "version": "1.0.0"}
        }
    }
    
    try:
        req = Request(base, method="POST")
        req.add_header("User-Agent", USER_AGENT)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        req.data = json.dumps(init_payload).encode()
        
        with urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                print(f"[!] HTTP 200 - MCP endpoint accepts unauthenticated requests", file=sys.stderr)
                return None, None
                
    except HTTPError as e:
        status = e.code
        
        if status != 401:
            print(f"[!] HTTP {status} - Expected 401", file=sys.stderr)
            return None, None
        
        # Step 2: Parse 401 for resource_metadata
        www_auth = e.headers.get("www-authenticate", "")
        print(f"[*] HTTP 401 - Server requires OAuth", file=sys.stderr)
        
        match = re.search(r'resource_metadata="([^"]+)"', www_auth)
        if not match:
            print(f"[!] No resource_metadata in www-authenticate", file=sys.stderr)
            return None, None
        
        resource_url = match.group(1)
        print(f"[*] Resource metadata: {resource_url}", file=sys.stderr)
        
        # Step 3: Fetch resource metadata
        try:
            req = Request(resource_url)
            req.add_header("User-Agent", USER_AGENT)
            
            with urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    resource_data = json.loads(resp.read().decode())
                    auth_servers = resource_data.get("authorization_servers", [])
                    print(f"[*] Found {len(auth_servers)} OAuth server(s)\n", file=sys.stderr)
                    
                    # Step 4: Fetch OAuth metadata from each auth server
                    endpoints = {}
                    for oauth_server in auth_servers:
                        print(f"[*] Fetching OAuth metadata from: {oauth_server}", file=sys.stderr)
                        
                        try:
                            oauth_url = oauth_server.rstrip("/") + "/.well-known/oauth-authorization-server"
                            req = Request(oauth_url)
                            req.add_header("User-Agent", USER_AGENT)
                            
                            with urlopen(req, timeout=5) as resp:
                                if resp.status == 200:
                                    oauth_data = json.loads(resp.read().decode())
                                    
                                    # Extract testable endpoints
                                    ep = {
                                        "token": oauth_data.get("token_endpoint"),
                                        "authorize": oauth_data.get("authorization_endpoint"),
                                        "register": oauth_data.get("registration_endpoint"),
                                        "revoke": oauth_data.get("revocation_endpoint"),
                                        "device": oauth_data.get("device_authorization_endpoint"),
                                        "jwks": oauth_data.get("jwks_uri"),
                                    }
                                    ep = {k: v for k, v in ep.items() if v}
                                    endpoints.update(ep)
                                    print(f"[+] Discovered {len(ep)} endpoints\n", file=sys.stderr)
                                    
                        except (HTTPError, URLError, socket.timeout, json.JSONDecodeError) as err:
                            print(f"[!] Failed: {err}", file=sys.stderr)
                            continue
                    
                    if endpoints:
                        discovery_info = {
                            "method": "RFC 9728 → RFC 8414",
                            "resource_metadata": resource_url,
                            "auth_servers": auth_servers,
                            "endpoints": endpoints
                        }
                        return endpoints, discovery_info
                        
        except (HTTPError, URLError, socket.timeout, json.JSONDecodeError) as err:
            print(f"[!] Failed to fetch resource metadata: {err}", file=sys.stderr)
    
    except (URLError, socket.timeout) as err:
        print(f"[!] Cannot reach {base}: {err}", file=sys.stderr)
    
    return None, None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: mcp_discovery.py <mcp_server_url>")
        sys.exit(1)
    
    endpoints, info = discover_oauth(sys.argv[1])
    
    if endpoints:
        print(f"\n{'='*80}")
        print("DISCOVERED OAUTH ENDPOINTS")
        print(f"{'='*80}\n")
        for name, url in endpoints.items():
            print(f"{name:15s}: {url}")
        print(f"\n{'='*80}\n")
        
        print(json.dumps({"endpoints": endpoints, "discovery_info": info}, indent=2))
    else:
        print("\n[!] OAuth discovery failed\n")
        sys.exit(1)

