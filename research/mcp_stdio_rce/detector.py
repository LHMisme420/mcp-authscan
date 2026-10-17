#!/usr/bin/env python3
"""Safe detector for an UNAUTHENTICATED MCP config / registration endpoint.

Flags the OX Security "unauthenticated config interface" precondition WITHOUT
exploiting it. It never registers a server and never submits a command to run:

  * Signal A -- it GETs common config/registry listing paths and flags one that
    returns an MCP server registry without authentication.
  * Signal B -- it POSTs an empty/malformed body to common registration paths;
    a *validation* error (HTTP 400) means the endpoint processed an
    unauthenticated request (auth not enforced), whereas 401/403 means it did
    not. The empty body guarantees nothing is registered or executed.

AUTHORIZATION: run this only against a server you operate or are explicitly
authorized to test (your own instance, or an in-scope bug-bounty asset whose
policy permits automated testing). Reachability is not permission.
"""
import argparse
import json

import requests

LISTING_PATHS = ("/mcp/servers", "/config/mcp", "/api/mcp/servers", "/v1/mcp/servers")
REGISTER_PATHS = ("/mcp/servers", "/api/mcp/servers", "/v1/mcp/servers")
REGISTRY_MARKERS = ("servers", "mcpservers", "command", "stdio")


def _looks_like_registry(text):
    low = text[:8192].lower()
    if not any(marker in low for marker in REGISTRY_MARKERS):
        return False
    try:
        return isinstance(json.loads(text), (dict, list))
    except ValueError:
        return False


def detect_unauth_mcp_config(base_url, timeout=5, session=None):
    """Return a finding dict if an unauthenticated config endpoint is found, else None."""
    http = session or requests
    base = base_url.rstrip("/")
    evidence = []

    for path in LISTING_PATHS:
        try:
            resp = http.get(f"{base}{path}", timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and _looks_like_registry(resp.text or ""):
            evidence.append(f"GET {path} -> 200 exposes MCP registry without auth")

    for path in REGISTER_PATHS:
        try:
            resp = http.post(f"{base}{path}", json={}, timeout=timeout)
        except requests.RequestException:
            continue
        # Empty body: a real auth gate answers 401/403 BEFORE validating input.
        if resp.status_code == 400:
            evidence.append(f"POST {path} -> 400 (processed unauthenticated request; auth not enforced)")

    if not evidence:
        return None
    return {
        "severity": "CRITICAL",
        "issue": "Unauthenticated MCP configuration/registration endpoint",
        "impact": "Class of OX Security config->STDIO-spawn RCE "
                  "(e.g. LiteLLM CVE-2026-30623). An unauthenticated registration "
                  "endpoint can spawn an attacker-supplied STDIO command.",
        "evidence": evidence,
        "remediation": "Require authentication on all MCP-config endpoints and "
                       "restrict registrable launchers to an allowlist.",
        "note": "Detection only -- no server was registered and no command was executed.",
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect an unauthenticated MCP config endpoint (authorized/local targets only).")
    parser.add_argument("url", help="base URL of a server you own or are authorized to test")
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()
    finding = detect_unauth_mcp_config(args.url, timeout=args.timeout)
    print(json.dumps(finding or {"status": "clean", "issue": None}, indent=2))


if __name__ == "__main__":
    main()
