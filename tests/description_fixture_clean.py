"""Answer-key fixture for the tool description probe (clean). Zero-auth MCP server; see
tests/fixtures/description_answer_key.json for the expected verdicts."""
import sys
from http.server import ThreadingHTTPServer

import mcp_fixture
from description_tools import CLEAN

mcp_fixture.TOOLS = CLEAN
mcp_fixture.RES = []
mcp_fixture.PROMPTS = []
ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), mcp_fixture.H).serve_forever()
