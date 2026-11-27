import os
import sys

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_http_headers
from fastmcp.server.middleware import Middleware

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
if MODE not in ("enforce", "open"):
    sys.exit('usage: h5.py enforce|open')

HOST = "127.0.0.1"
PORT = int(os.environ.get("H5_PORT", "8765"))
EXPECTED = "Bearer synthetic-token"


class CallToolGate(Middleware):
    """Gate only tools/call. initialize and tools/list pass through untouched."""

    async def on_call_tool(self, context, call_next):
        if MODE == "enforce":
            # include_all=True: by default get_http_headers strips 'authorization'.
            headers = get_http_headers(include_all=True)
            if headers.get("authorization") != EXPECTED:
                print("MARKER reject tools/call", flush=True)
                raise ToolError("unauthorized: tools/call requires a valid bearer token")
        print("MARKER allow tools/call", flush=True)
        return await call_next(context)


mcp = FastMCP("h5", middleware=[CallToolGate()])


@mcp.tool
def probe_ping() -> str:
    """returns pong"""
    print("MARKER executed probe_ping", flush=True)
    return "pong"


if __name__ == "__main__":
    print(f"MARKER start {MODE}", flush=True)
    mcp.run(transport="http", host=HOST, port=PORT, path="/mcp", show_banner=False)
