#!/usr/bin/env python3
"""Standalone CLI for the MCP RCE-precondition detectors.

The detection logic lives in the installed package (``mcp_authscan.rce_checks``)
so the main scanner can reuse it via ``--checks all``; this script is the
local-research CLI around the same functions, printing findings as JSON.

It runs two safe checks and never exploits anything: it does not register an MCP
server, submit a command to run, or make tool calls.

AUTHORIZATION: run this only against a server you operate or are explicitly
authorized to test (your own instance, or an in-scope bug-bounty asset whose
policy permits automated testing). Reachability is not permission.
"""
import argparse
import json

from mcp_authscan.rce_checks import (
    detect_dns_rebinding_precondition,
    detect_unauth_mcp_config,
)


def main():
    parser = argparse.ArgumentParser(
        description="Detect MCP config/DNS-rebinding preconditions (authorized/local targets only).")
    parser.add_argument("url", help="base URL of a server you own or are authorized to test")
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()
    findings = [f for f in (
        detect_unauth_mcp_config(args.url, timeout=args.timeout),
        detect_dns_rebinding_precondition(args.url, timeout=args.timeout),
    ) if f]
    print(json.dumps(findings or {"status": "clean", "findings": []}, indent=2))


if __name__ == "__main__":
    main()
