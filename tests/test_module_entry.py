"""`python3 -m mcp_authscan` is the console script: same --help bytes, same --version."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(sys.executable).parent / "mcp-authscan"
ENV = dict(os.environ, COLUMNS="100")


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, env=ENV, stdin=subprocess.DEVNULL, timeout=60)


@pytest.mark.skipif(not SCRIPT.exists(), reason="console script not installed next to this python")
@pytest.mark.parametrize("flag", ["--help", "--version"])
def test_module_matches_console_script(flag):
    mod = _run([sys.executable, "-m", "mcp_authscan", flag])
    con = _run([str(SCRIPT), flag])
    assert con.returncode == 0, con.stderr
    assert mod.returncode == con.returncode, mod.stderr.decode(errors="replace")
    assert mod.stdout == con.stdout
