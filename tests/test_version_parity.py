"""Every place the scanner states its own version must agree.

`pyproject.toml` and `mcp_authscan.__version__` say 1.1.3, while the CLI banner
(`--help`), the report footer ("Scanner: mcp-authscan v..."), the SARIF
tool.version field and the User-Agent header all come from a hard-coded
`VERSION` literal in `monolith.py`, which still said 1.1.2 - so the tool
reported a release that was never published, and triage notes quoted it.

`PROBE_SET_VERSION` is deliberately *not* derived from the release version: it
is part of the report's reproducibility contract (it feeds the report hash), so
a release bump must not silently renumber the probe set. The last test pins it
separately.
"""
import re
import subprocess
import sys
from pathlib import Path

import mcp_authscan
from mcp_authscan import monolith, scan_main

REPO_ROOT = Path(__file__).resolve().parents[1]


def _pyproject_version() -> str:
    """Read the version from pyproject without requiring tomllib (py3.8+)."""
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    assert match, "no version found in pyproject.toml"
    return match.group(1)


def test_package_version_matches_pyproject():
    assert mcp_authscan.__version__ == _pyproject_version()


def test_module_version_literals_match_package():
    """monolith/scan_main must not carry their own version literals."""
    assert monolith.VERSION == mcp_authscan.__version__, (
        f"monolith.VERSION={monolith.VERSION!r} disagrees with package "
        f"{mcp_authscan.__version__!r}"
    )
    assert scan_main.VERSION == mcp_authscan.__version__, (
        f"scan_main.VERSION={scan_main.VERSION!r} disagrees with package "
        f"{mcp_authscan.__version__!r}"
    )


def test_cli_help_advertises_package_version():
    """The only version a user sees without scanning is the --help banner."""
    result = subprocess.run(
        [sys.executable, "-m", "mcp_authscan.cli_wrapper", "--help"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert "v" + mcp_authscan.__version__ in result.stdout, (
        f"CLI does not advertise {mcp_authscan.__version__!r}; got:\n{result.stdout}"
    )


def test_probe_set_version_is_independent_of_release_version():
    """The probe set has its own version; the release version must not move it."""
    assert monolith.PROBE_SET_VERSION == "1.1.0"
    assert scan_main.PROBE_SET_VERSION == monolith.PROBE_SET_VERSION
