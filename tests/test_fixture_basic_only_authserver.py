#!/usr/bin/env python3
"""Test server: the 9004 full authorization server (test_fixture_full_authserver.py) on 9005 with
client authentication narrowed to client_secret_basic. /token, /revoke and /device refuse a client
that sends its secret in the body (client_secret_post) with 401 invalid_client, exactly as they
refuse a request with no credentials; the metadata advertises client_secret_basic only and
registration echoes client_secret_basic. Everything else is the 9004 server unchanged."""
import os
import sys
from http.server import HTTPServer

if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import test_fixture_full_authserver as server
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9005
    server.BASE = "http://127.0.0.1:%d" % port
    server.ACCEPTED_AUTH_METHODS = ("client_secret_basic",)
    HTTPServer(("127.0.0.1", port), server.FullAuthServerHandler).serve_forever()
