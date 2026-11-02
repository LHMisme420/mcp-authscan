import pathlib
import re
from importlib.metadata import version

from mcp_authscan.oauth_probes_v2 import USER_AGENT

HARDCODED = re.compile(r"mcp-authscan/\d")


def test_user_agent_tracks_installed_version():
    assert USER_AGENT == "mcp-authscan/" + version("mcp-authscan")


def test_no_probe_hardcodes_a_user_agent_version():
    root = pathlib.Path.cwd() / "mcp_authscan"
    assert root.is_dir(), "run pytest from the repo root"
    bad = [str(p) for p in root.rglob("*.py") if HARDCODED.search(p.read_text())]
    assert bad == [], bad
