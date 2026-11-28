from importlib.metadata import PackageNotFoundError, distribution, version as pkgversion  # noqa: F401
# The installed distribution's metadata (built from the root pyproject.toml) is the only source,
# but only when that distribution owns this file. Metadata from some other copy (a stale install
# while running from a tree) is never reported as this code's version.
# tests/test_version_single_source.py fails when any other declaration disagrees with it.


def _owned_version(dist, here):
    import json
    from pathlib import Path
    from urllib.parse import unquote, urlparse
    here = Path(here).resolve()
    try:
        if Path(dist.locate_file("mcp_authscan/__init__.py")).resolve() == here:
            return dist.version
    except Exception:
        pass
    try:
        url = json.loads(dist.read_text("direct_url.json") or "{}").get("url", "")
    except Exception:
        url = ""
    if url.startswith("file://") and Path(unquote(urlparse(url).path)).resolve() == here.parent.parent:
        return dist.version
    return dist.version + "+not-this-tree"


try:
    __version__ = _owned_version(distribution("mcp-authscan"), __file__)
except PackageNotFoundError:
    __version__ = "0.0.0+source"

__all__ = ["MCPScanner", "SecurityReport"]


def __getattr__(name):
    if name == "MCPScanner":
        from .scanner import MCPScanner
        return MCPScanner
    if name == "SecurityReport":
        from .report import SecurityReport
        return SecurityReport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
