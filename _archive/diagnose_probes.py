#!/usr/bin/env python3
"""Diagnose exact HTTP statuses for each probe against a target."""
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import socket

if len(sys.argv) < 2:
    print("Usage: python3 diagnose_probes.py <target_url>")
    sys.exit(1)

target = sys.argv[1]

print(f"\n{'='*80}")
print(f"PROBE DIAGNOSTICS: {target}")
print(f"{'='*80}\n")

for path, method in [("/sse", "GET"), ("/message", "POST"), ("/mcp", "POST"), ("/tools/list", "GET")]:
    url = target.rstrip("/") + path

    # Test 1: No auth
    try:
        req = Request(url, method=method)
        with urlopen(req, timeout=5) as resp:
            status = resp.status
            result = "VULNERABLE" if status in [200, 201, 202] else ("PASS" if status in [401, 403] else "NOT_OBSERVED")
            print(f"[D1-zero-auth] {method:4s} {path:15s} -> HTTP {status:3d}  ({result})")
    except HTTPError as e:
        status = e.code
        result = "VULNERABLE" if status in [200, 201, 202] else ("PASS" if status in [401, 403] else "NOT_OBSERVED")
        print(f"[D1-zero-auth] {method:4s} {path:15s} -> HTTP {status:3d}  ({result})")
    except (URLError, socket.timeout) as e:
        print(f"[D1-zero-auth] {method:4s} {path:15s} -> CONNECTION FAILED")

print(f"\n{'='*80}")
print("\nInterpretation:")
print("  200/201/202 = VULNERABLE (server accepts unauthenticated requests)")
print("  401/403     = PASS (server correctly rejects)")
print("  404/5xx     = NOT_OBSERVED (endpoint doesn't exist or server error)")
print("  ConnFail    = NOT_OBSERVED (can't reach server)")
print(f"{'='*80}\n")
