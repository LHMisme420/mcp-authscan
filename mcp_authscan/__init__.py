from importlib.metadata import version as pkgversion
try:
    __version__ = "1.1.20"
except Exception:
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
