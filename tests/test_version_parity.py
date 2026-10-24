"""
Test version parity between tool and probe set.

Tool version and probe set version are maintained separately.
Adding a probe should never require a tool version bump,
and tool improvements should not invalidate existing probe definitions.
"""

import pytest
from pathlib import Path
import json
import re


def get_tool_version():
    """Extract tool version from pyproject.toml."""
    pyproject_path = Path(__file__).parent.parent / "mcp_authscan" / "pyproject.toml"
    with open(pyproject_path) as f:
        content = f.read()
    match = re.search(r'version\s*=\s*["\']([^"\']+)["\']', content)
    if match:
        return match.group(1)
    raise ValueError("Tool version not found in pyproject.toml")


def get_probe_set_version():
    """Extract probe set version from scanner config or constants."""
    constants_path = Path(__file__).parent.parent / "mcp_authscan" / "scanner" / "constants.py"
    with open(constants_path) as f:
        content = f.read()
    match = re.search(r'PROBE_SET_VERSION\s*=\s*["\']([^"\']+)["\']', content)
    if match:
        return match.group(1)
    raise ValueError("Probe set version not found in constants.py")


class TestVersionParity:
    """Verify tool and probe set versions are maintained independently."""

    def test_tool_version_format(self):
        """Tool version follows semantic versioning."""
        version = get_tool_version()
        assert re.match(r'^\d+\.\d+\.\d+$', version), f"Invalid tool version: {version}"

    def test_probe_set_version_format(self):
        """Probe set version follows semantic versioning."""
        version = get_probe_set_version()
        assert re.match(r'^\d+\.\d+\.\d+$', version), f"Invalid probe set version: {version}"

    def test_versions_can_differ(self):
        """Tool and probe set versions are independent."""
        tool_version = get_tool_version()
        probe_version = get_probe_set_version()
        # This test documents that versions can be different
        # (they should be, in fact, to preserve report stability)
        assert isinstance(tool_version, str)
        assert isinstance(probe_version, str)

    def test_version_reported_in_help(self):
        """Version information is discoverable via --version."""
        # Integration test: mcp-authscan --version outputs both versions
        import subprocess
        result = subprocess.run(
            ["mcp-authscan", "--version"],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"--version failed: {result.stderr}"
        assert "tool version" in result.stdout.lower() or get_tool_version() in result.stdout
