#!/usr/bin/env python3
"""Repository mode scanner executable for VATA."""
import sys

if __name__ == '__main__':
    from mcp_authscan.cli_wrapper import main
    sys.exit(main())
