"""Discovery must not fetch URLs the target chose into the scanner's own network.

The RFC 9728 discovery chain hands the scanner three URLs that come from the
target's HTTP responses, not from the operator:

    WWW-Authenticate: ... resource_metadata="<attacker-chosen>"
    {"authorization_servers": ["<attacker-chosen>", ...]}   (from that document)
    {"resource_metadata": ...} stored in discovery_info      (re-fetched later)

A server that answers 401 with `resource_metadata="http://169.254.169.254/..."`
or `"http://100.64.0.1/..."` (Tailscale/CGNAT) made the scanner issue that
request with its own network position, and a 302 let the target pick the
destination *after* any check on the first URL.

These tests are address-level and redirect-level; they never contact a public
host. `allow_private=True` is passed only where the loopback fixture itself is
the subject, which is the same opt-in `--allow-private` gives an operator.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_authscan import monolith, scan_main

MODULES = [monolith, scan_main]

# Addresses a target could name to reach the scanner's own network, all of
# which the old hand-written range list missed or never inspected.
REFUSED_URLS = [
    "http://127.0.0.1/token",              # loopback
    "http://169.254.169.254/latest/meta",   # cloud metadata (link-local)
    "http://100.64.0.1/token",              # CGNAT / Tailscale
    "http://0.0.0.0/token",                 # "any" address
    "http://[::ffff:127.0.0.1]/token",      # IPv4-mapped IPv6 loopback
    "http://[::1]/token",                   # IPv6 loopback
    "file:///etc/passwd",                   # not an HTTP fetch at all
]


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
@pytest.mark.parametrize("url", REFUSED_URLS)
def test_refuses_non_public_and_non_http(module, url):
    with pytest.raises(ValueError):
        module.assert_url_is_fetchable(url)


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
def test_allows_a_globally_routable_address(module):
    # IP literal: no DNS lookup, no connection.
    module.assert_url_is_fetchable("https://93.184.216.34/mcp")


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
def test_allow_private_opts_back_in(module):
    module.assert_url_is_fetchable("http://127.0.0.1/token", allow_private=True)


class _Redirecting(BaseHTTPRequestHandler):
    target = "/vars"

    def do_GET(self):  # noqa: N802 - stdlib naming
        self.send_response(302)
        self.send_header("Location", self.target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


@pytest.fixture()
def redirect_server():
    server = HTTPServer(("127.0.0.1", 0), _Redirecting)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/token"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("module", MODULES, ids=["monolith", "scan_main"])
def test_redirects_are_refused_not_followed(module, redirect_server):
    """A 30x lets the target pick the destination after the address check."""
    from urllib.request import Request

    req = Request(redirect_server)
    with pytest.raises(Exception) as excinfo:
        module.open_without_redirects(req, timeout=5)
    assert "redirect" in str(excinfo.value).lower() or "302" in str(excinfo.value)
