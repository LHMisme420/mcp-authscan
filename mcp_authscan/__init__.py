try:
    from importlib.metadata import version
    __version__ = version("mcp-authscan")
except (ImportError, ModuleNotFoundError, Exception):
    __version__ = "1.1.9"  # fallback with current release version

__all__ = ["MCPScanner", "SecurityReport"]


def __getattr__(name):
    # Keep the shared CORS policy importable by the stdlib-only live CLI.
    if name == "MCPScanner":
        from .scanner import MCPScanner
        return MCPScanner
    if name == "SecurityReport":
        from .report import SecurityReport
        return SecurityReport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
