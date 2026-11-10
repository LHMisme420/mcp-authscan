import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from urllib.request import Request

from mcp_authscan.oauth_probes_v2 import EgressRefusalError, _egress_guard

class _Redirecting(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", "http://127.0.0.2/out-of-scope")
        self.send_header("Content-Length", "0")
        self.end_headers()

def test_redirect_out_of_scope_is_refused():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Redirecting)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = Request("http://127.0.0.1:%d/start" % port)
        with pytest.raises(EgressRefusalError) as exc:
            _egress_guard(req, allow_private=True, allowed_hosts={"127.0.0.1"})
        assert "127.0.0.2" in str(exc.value)
    finally:
        srv.shutdown()
