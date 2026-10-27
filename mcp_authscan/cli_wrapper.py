"""Package entry point: call the monolith."""
import sys
from . import monolith

def main():
    """Call monolith main, catching any unhandled exceptions."""
    try:
        monolith.main()
    except SystemExit:
        raise
    except BaseException as e:
        print(f"[!] scan failed: {type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(4)

if __name__ == "__main__":
    main()
