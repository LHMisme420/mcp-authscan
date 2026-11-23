"""Every outbound request in monolith goes through the OAuth probes' guarded transport,
so a target that 302-redirects to a protected local address cannot be followed.

A front server on an authorized loopback host (127.0.0.1) redirects to a sentinel on a
different, UNauthorized loopback peer (127.0.0.2). No connection may reach the sentinel.
No cloud metadata and no third-party host are touched.
"""
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

from mcp_authscan import monolith

PROTECTED_HOST = "127.0.0.2"   # loopback peer, deliberately NOT in the authorized set
FRONT_HOST = "127.0.0.1"       # authorized front hop


class _Sentinel:
    """Listener on the protected address that records any inbound connection."""
    def __init__(self, host):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, 0))
        self.sock.listen(5)
        self.sock.settimeout(0.5)
        self.host, self.port = self.sock.getsockname()
        self.connections = 0
        self._stop = False
        self._t = threading.Thread(target=self._run, daemon=True)
        self._t.start()

    def _run(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
                self.connections += 1
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def close(self):
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass
        self._t.join(timeout=2)


def _redirector(location):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", location)
            self.end_headers()

        def log_message(self, *args):
            pass

    srv = HTTPServer((FRONT_HOST, 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_redirect_to_protected_local_address_is_never_connected(monkeypatch):
    sentinel = _Sentinel(PROTECTED_HOST)
    srv = _redirector(f"http://{PROTECTED_HOST}:{sentinel.port}/")
    front_port = srv.server_address[1]
    # Authorize only the front host; permit loopback so the front hop itself connects.
    # The protected peer is a different host, so it is not in the authorized set.
    monkeypatch.setattr(monolith, "ALLOWED_HOSTS", {FRONT_HOST})
    monkeypatch.setattr(monolith, "ALLOW_PRIVATE_TARGETS", True)
    try:
        monolith._direct_rfc8414_discovery(f"http://{FRONT_HOST}:{front_port}")
        time.sleep(0.4)  # let any stray connection land before asserting
        assert sentinel.connections == 0, (
            "a request reached the protected address "
            f"{PROTECTED_HOST}:{sentinel.port} ({sentinel.connections} connection(s)); "
            "the redirect was followed instead of refused")
    finally:
        srv.shutdown()
        sentinel.close()
