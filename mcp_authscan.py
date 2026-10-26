#!/usr/bin/env python3
"""Compatibility entry point for the web runner's offline source-scan contract.

Scanner rules live in the package. The web runner passes a local clone directory
and --json, after checking and recording the user's target authorization. Other
invocations retain the package CLI's authorization and live-target safeguards.
"""
import json
from pathlib import Path
import sys

from mcp_authscan import monolith


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[1] == "--json" and Path(args[0]).is_dir():
        # Static analysis only: never execute cloned code or make HTTP probes.
        findings = monolith.scan(args[0], include_tests=False)
        print(json.dumps({"count": len(findings), "findings": findings}))
        return
    monolith.main()


if __name__ == "__main__":
    main()
