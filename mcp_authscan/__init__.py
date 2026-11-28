from importlib.metadata import PackageNotFoundError, version as pkgversion
# The installed distribution's metadata (built from the root pyproject.toml) is the only source.
# tests/test_version_single_source.py fails when any other declaration disagrees with it.
try:
    __version__ = pkgversion("mcp-authscan")
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
