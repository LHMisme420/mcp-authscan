"""`python3 -m mcp_authscan`: the same entry point as the `mcp-authscan` console script."""
import sys

from mcp_authscan.cli_wrapper import main

if __name__ == "__main__":
    # argparse takes its prog name from argv[0]; use the console script's name so
    # `--help` is byte-identical to `mcp-authscan --help`.
    sys.argv[0] = "mcp-authscan"
    sys.exit(main())
