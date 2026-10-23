"""Thin wrapper: package entry point calls the monolith."""
import sys
import runpy

def main():
    """Call the monolith as __main__."""
    sys.argv[0] = "mcp-authscan"
    runpy.run_path("mcp_authscan.py", run_name="__main__")

if __name__ == "__main__":
    main()
