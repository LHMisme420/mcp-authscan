"""The installed package metadata is the only version source; every other declaration must agree."""
import re
import tomllib
from importlib.metadata import version
from pathlib import Path

import mcp_authscan
from mcp_authscan import releases

ROOT = Path(__file__).resolve().parents[1]
META = version("mcp-authscan")


def declarations():
    return {
        "pyproject.toml": tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"],
        "mcp_authscan/pyproject.toml": tomllib.loads((ROOT / "mcp_authscan" / "pyproject.toml").read_text())["project"]["version"],
        "CITATION.cff": re.search(r"(?m)^version:\s*(\S+)", (ROOT / "CITATION.cff").read_text()).group(1),
        "README.md": re.search(r"Current source version (\S+)", (ROOT / "README.md").read_text()).group(1),
        "mcp_authscan.__version__": mcp_authscan.__version__,
    }


def test_every_declaration_equals_package_metadata():
    bad = {k: v for k, v in declarations().items() if v != META}
    assert not bad, "metadata says %s; disagreeing: %s" % (META, bad)


def test_init_declares_no_literal_version():
    src = (ROOT / "mcp_authscan" / "__init__.py").read_text()
    assert not re.search(r'__version__\s*=\s*"(?!0\.0\.0\+source")\d', src), "__init__.py must read metadata, not hardcode"


def test_running_version_is_a_shipped_or_planned_release():
    assert any(META in v for v in releases.PROBE_SET_RELEASES.values())
