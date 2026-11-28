"""The installed package metadata is the only version source; every other declaration must agree."""
import json
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


class _Dist:
    def __init__(self, ver, located, url=None):
        self.version, self._located, self._url = ver, located, url

    def locate_file(self, rel):
        return self._located

    def read_text(self, name):
        return json.dumps({"url": self._url}) if (name == "direct_url.json" and self._url) else None


def test_metadata_used_only_when_it_owns_the_running_file(tmp_path):
    from mcp_authscan import _owned_version
    tree = tmp_path / "tree"; (tree / "mcp_authscan").mkdir(parents=True)
    here = tree / "mcp_authscan" / "__init__.py"; here.write_text("")
    other = tmp_path / "site-packages" / "mcp_authscan" / "__init__.py"
    other.parent.mkdir(parents=True); other.write_text("")
    # installed copy is this file
    assert _owned_version(_Dist("1.1.51", here), here) == "1.1.51"
    # editable install pointing at this tree
    assert _owned_version(_Dist("1.1.51", other, "file://%s" % tree), here) == "1.1.51"
    # metadata from another copy: never reported as this tree's version
    assert _owned_version(_Dist("1.1.45", other, "file:///somewhere/else"), here) == "1.1.45+not-this-tree"
