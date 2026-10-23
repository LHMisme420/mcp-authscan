"""Regression: a 401 whose WWW-Authenticate header has no RFC 9728 pointer.

`discover_oauth_endpoints()` reads the pointer with

    match = re.search(r'resource_metadata="([^"]+)"', www_auth)
    if not match:
        print("... trying direct RFC 8414")   # message says it will try
    else:
        resource_url = match.group(1)
    resource_parsed = urlparse(resource_url)  # UnboundLocalError when no match

so a server that answers 401 with a plain `WWW-Authenticate: Bearer realm=...`
header - the common shape for servers that never implemented RFC 9728 - kills
the scan with an unhandled UnboundLocalError instead of falling through to
direct RFC 8414 discovery on the base URL.

`scan_main.py` does not crash: it returns early and never attempts the direct
fallback, so the two entry points disagree about what a pointerless 401 means.

The fixture below is a loopback HTTP server. It answers the MCP initialize POST
with a pointerless 401 and serves an RFC 8414 document, which lets the test
assert the *positive* outcome (discovery succeeds) rather than merely the
absence of an exception.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_authscan import monolith, scan_main


class _Pointerless401Handler(BaseHTTPRequestHandler):
    """401 with no resource_metadata parameter, plus an RFC 8414 document."""

    seen_paths = []

    def do_POST(self):  # noqa: N802 - stdlib naming
        type(self).seen_paths.append(("POST", self.path))
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="example"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):  # noqa: N802 - stdlib naming
        type(self).seen_paths.append(("GET", self.path))
        if "/.well-known/oauth-authorization-server" in self.path:
            body = json.dumps(
                {
                    "token_endpoint": "https://auth.example.com/token",
                    "authorization_endpoint": "https://auth.example.com/authorize",
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):  # keep pytest output clean
        pass


@pytest.fixture()
def pointerless_401_server():
    _Pointerless401Handler.seen_paths = []
    server = HTTPServer(("127.0.0.1", 0), _Pointerless401Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("module", [monolith, scan_main], ids=["monolith", "scan_main"])
def test_pointerless_401_falls_back_to_direct_rfc8414(module, pointerless_401_server):
    """A 401 without a discovery pointer must reach direct RFC 8414 discovery.

    Before the fix this raises UnboundLocalError on monolith and returns
    (None, None) on scan_main without ever requesting the well-known document.
    """
    endpoints, discovery_info = module.discover_oauth_endpoints(pointerless_401_server)

    assert endpoints is not None, (
        "discovery gave up on a pointerless 401 instead of trying direct RFC 8414"
    )
    assert endpoints.get("token") == "https://auth.example.com/token"
    assert discovery_info["method"] == "RFC 8414 direct"

    requested = [path for _method, path in _Pointerless401Handler.seen_paths]
    assert any(path.startswith("/.well-known/oauth-authorization-server") for path in requested), (
        "the direct RFC 8414 document was never requested"
    )


def test_pointerless_401_never_raises_unbound_local(pointerless_401_server):
    """The specific failure mode from the audit: UnboundLocalError on monolith."""
    try:
        monolith.discover_oauth_endpoints(pointerless_401_server)
    except UnboundLocalError as exc:  # pragma: no cover - the bug itself
        pytest.fail(f"pointerless 401 raised UnboundLocalError: {exc}")
