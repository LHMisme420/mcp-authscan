"""The mcp-authscan console script that belongs to the interpreter running the tests.

Tests must never run whatever mcp-authscan comes first on PATH: a stale install elsewhere
(1.1.22, 1.1.45 have both happened) would be tested instead of this tree.
"""
import os
import sys

SCANNER = os.path.join(os.path.dirname(sys.executable), "mcp-authscan")
if not os.access(SCANNER, os.X_OK):
    raise RuntimeError("no mcp-authscan console script next to %s; run: %s -m pip install -e ." % (sys.executable, sys.executable))
