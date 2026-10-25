#!/usr/bin/env python3
"""
Merge live server scanning into mcp_authscan.py
Adds ability to scan both source code AND running MCP servers
"""
import sys

# Read the original
with open('mcp_authscan.py', 'r') as f:
    content = f.read()

# Find where to insert live scanning (after imports, before VERSION)
insert_marker = 'VERSION = "0.9.4"'
insert_pos = content.find(insert_marker)

if insert_pos == -1:
    print("ERROR: Could not find VERSION marker")
    sys.exit(1)

# Live scanning code to add
live_scan_code = '''
# ---- Live MCP Server Scanning ----
import socket
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlparse
from mcp_authscan.cors import probe_cors_urllib

LIVE_ENDPOINTS = {
    "/sse": "GET",
    "/message": "POST", 
    "/mcp": "POST",
    "/tools/list": "GET",
}

def scan_live_server(target_url):
    """Scan a running MCP server for zero-auth, CORS, token validation issues."""
    findings = []
    try:
        p = urlparse(target_url)
        socket.create_connection((p.hostname, p.port or 80), timeout=5)
    except Exception as e:
        print(f"[!] Cannot reach {target_url}: {e}", file=sys.stderr)
        return findings
    
    print(f"[*] Scanning live MCP server: {target_url}", file=sys.stderr)
    
    for path, method in LIVE_ENDPOINTS.items():
        url = target_url.rstrip("/") + path
        
        # Test 1: Zero-auth endpoint
        try:
            req = Request(url, method=method)
            req.add_header("User-Agent", f"mcp-authscan/{VERSION}")
            if method == "POST":
                req.data = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'.encode()
                req.add_header("Content-Type", "application/json")
            
            with urlopen(req, timeout=5) as resp:
                if resp.status in [200, 201, 202]:
                    add(findings, "D1", "CRITICAL",
                        f"Zero-auth endpoint: {method} {path}",
                        url, "", 0,
                        f"Endpoint accessible without Authorization header (HTTP {resp.status})",
                        "D1-zero-auth", "HIGH")
        except HTTPError as e:
            if e.code in [200, 201, 202]:
                add(findings, "D1", "CRITICAL", f"Zero-auth: {method} {path}",
                    url, "", 0, f"HTTP {e.code} without auth", "D1-zero-auth", "HIGH")
        except (URLError, socket.timeout): pass
        
        # Test 2: Evidence-based CORS policy
        try:
            assessment = probe_cors_urllib(url, method, timeout=5, opener=urlopen)
            if assessment.is_finding:
                add(findings, "D2", assessment.severity, f"{assessment.summary} on {path}",
                    url, "", 0, assessment.details,
                    "D2-cors-origin-reflection" if assessment.reflected else "D2-cors-wildcard", "MEDIUM")
        except (HTTPError, URLError, socket.timeout): pass
        
        # Test 3: Invalid token accepted
        try:
            req = Request(url, method=method)
            req.add_header("Authorization", "Bearer invalid_token_xyz")
            if method == "POST":
                req.data = '{"jsonrpc":"2.0"}'.encode()
                req.add_header("Content-Type", "application/json")
            
            with urlopen(req, timeout=5) as resp:
                if resp.status in [200, 201, 202]:
                    add(findings, "D3", "HIGH", f"Token validation bypass on {path}",
                        url, "", 0, "Invalid Bearer token accepted", "D3-token-validation", "HIGH")
        except HTTPError as e:
            if e.code in [200, 201, 202]:
                add(findings, "D3", "HIGH", f"Token validation bypass on {path}",
                    url, "", 0, "Invalid token accepted", "D3-token-validation", "HIGH")
        except (URLError, socket.timeout): pass
    
    return findings

'''

# Insert the live scanning code
content = content[:insert_pos] + live_scan_code + content[insert_pos:]

# Now update the main() function to auto-detect
old_main_scan = "F = scan(args.target, args.include_tests, args.exclude)"
new_main_scan = """# Auto-detect: live server (http(s)://) or source code directory?
    if args.target.startswith("http://") or args.target.startswith("https://"):
        print(f"[*] Detected live server URL", file=sys.stderr)
        F = scan_live_server(args.target)
    else:
        print(f"[*] Scanning source code directory", file=sys.stderr)
        F = scan(args.target, args.include_tests, args.exclude)"""

content = content.replace(old_main_scan, new_main_scan)

# Update help text
old_help = 'ap.add_argument("target", help="path to MCP server repo/dir")'
new_help = 'ap.add_argument("target", help="path to MCP server repo/dir OR http(s)://host:port for live scanning")'
content = content.replace(old_help, new_help)

# Write back
with open('mcp_authscan.py', 'w') as f:
    f.write(content)

print("[+] Live server scanning merged into mcp_authscan.py")
print("[+] Tool now scans both source code AND running servers")
