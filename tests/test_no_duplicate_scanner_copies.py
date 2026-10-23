"""Guard against editor leftovers and a mis-filed binary in the repo root.

The repo root had accumulated five copies of the scanner plus a 107 KB file
named `claude.AppImage` that was actually a saved Next.js error page:

    mcp_authscan.py                  <- load-bearing, see below
    mcp_authscan.py.backup           <- byte-identical to .bak2, unreferenced
    mcp_authscan.py.bak2             <- byte-identical to .backup, unreferenced
    mcp_authscan_updated.py          <- 84-line fragment of a rule patch
    claude.AppImage                  <- HTML, not an AppImage

The backups and the HTML file are gone. `mcp_authscan.py` is *not* junk and
must not be deleted: `mcp_authscan/repository_scan.py` resolves it as the
scanner executable for repository mode, CI runs `py_compile`/`mypy` on it, and
`proof_all_exit_codes.sh` invokes it. The second test below pins that
dependency so a future cleanup does not break repository scanning while
removing "a duplicate".
"""
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

JUNK_PATTERNS = ("*.py.backup", "*.py.bak", "*.py.bak2", "*.py.orig", "*.AppImage")


def test_no_backup_or_binary_leftovers_at_repo_root():
    offenders = []
    for pattern in JUNK_PATTERNS:
        offenders.extend(sorted(p.name for p in REPO_ROOT.glob(pattern)))
    assert not offenders, (
        "editor/binary leftovers in the repo root: " + ", ".join(offenders)
    )


def test_root_scanner_copy_is_still_the_one_repository_scan_uses():
    """Deleting the root copy as a 'duplicate' would break repository mode."""
    from mcp_authscan import repository_scan

    scanner = Path(repository_scan.scanner_path())
    assert scanner.exists(), f"repository mode points at a missing file: {scanner}"
    assert scanner.name == "mcp_authscan.py"
    assert scanner.parent == REPO_ROOT
