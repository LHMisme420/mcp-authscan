"""Package entry point: call the monolith."""
import sys
from . import monolith

def main():
    """Call monolith main, catching any unhandled exceptions."""
    # Handle --version flag
    if "--version" in sys.argv:
        from . import __version__
        print(f"mcp-authscan {__version__}")
        sys.exit(0)
    
    try:
        monolith.main()
    except SystemExit:
        raise
    except BaseException as e:
        print(f"[!] scan failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(4)

if __name__ == "__main__":
    main()
