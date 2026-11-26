"""Package entry point: call the monolith."""
import sys
from . import monolith

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "assurance":
        from .assurance import main as assurance_main
        return assurance_main(sys.argv[2:])
    if len(sys.argv) > 1 and sys.argv[1] == "challenge":
        from .deployment_ack import main as challenge_main
        return challenge_main(sys.argv[2:])
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
    sys.exit(main())
