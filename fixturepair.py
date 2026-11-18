#!/usr/bin/env python3
"""Mint a token for resource one, present it to resource two.

This builds directly on the existing OAuth fixture server
``tests/fixtures/audience_fixture.py``. That handler already does both halves of
the job we need:

  * the authorization side -- ``POST /token`` mints an audience-bound token
    (``client_credentials``) whose ``aud`` is the requested ``resource``;
  * the validation side -- ``POST /mcp`` reads the presented token's ``aud`` and,
    unless the server is permissive, refuses a token whose ``aud`` is not its own
    resource.

So "a second resource server using the same validation code" is literally a second
instance of ``audience_fixture.Handler``. We run two instances in one process:

  resource one  (port R1)  -- the authorization side; mints the token (aud = R1/mcp)
  resource two  (port R2)  -- the second resource; validates the presented token

Resource two's treatment of a token minted for resource one is governed by the
fixture's own ``PERMISSIVE`` switch:

  default (permissive)  accepts a token minted for the first resource  -> FOREIGN ACCEPTED
  strict                refuses it                                     -> FOREIGN REFUSED

Why one process: the fixture issues opaque tokens held in an in-process dict
(``audience_fixture.TOKENS``). A resource server in a *separate* process could not
see a token minted elsewhere, so there would be nothing to validate. Sharing the
token store in-process is a property of the existing fixture, not a new design; the
two servers here are the same ``Handler`` class over the same ``TOKENS`` dict.

Usage:
    python3 fixturepair.py [default|strict]

Verdict line is ``FOREIGN ACCEPTED`` (exit 1) or ``FOREIGN REFUSED`` (exit 0).
"""
import json
import os
import socket
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(ROOT, "tests", "fixtures"))

# The existing OAuth fixture server. Importing it is side-effect free: its own
# server only starts under `if __name__ == "__main__"`.
import audience_fixture as af  # noqa: E402


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _serve(port):
    """Start one audience_fixture.Handler instance on 127.0.0.1:port."""
    httpd = ThreadingHTTPServer(("127.0.0.1", port), af.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def _wait(port, timeout=5.0):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("fixture on port %d did not start" % port)


def _mint(base, resource):
    """Mint a client_credentials token at <base>/token for `resource` (its aud)."""
    body = "&".join([
        "grant_type=client_credentials",
        "client_id=%s" % af.CLIENT_ID,
        "client_secret=%s" % af.CLIENT_SECRET,
        "resource=%s" % resource,
    ]).encode()
    req = urllib.request.Request(base + "/token", data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=5) as r:
        payload = json.loads(r.read())
    tok = payload.get("access_token")
    if not tok:
        raise RuntimeError("authorization side did not issue a token: %s" % payload)
    return tok


def _present(base, token):
    """Present `token` to <base>/mcp. Return the HTTP status the resource answers."""
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                  "clientInfo": {"name": "fixturepair", "version": "1.0"}}}).encode()
    req = urllib.request.Request(base + "/mcp", data=body, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def run(mode):
    # `PERMISSIVE` is the fixture's own module-level switch, read by Handler.mcp on
    # every request. default -> accept a foreign aud; strict -> refuse it. We only
    # ever validate at resource two, so this single switch governs the one check we
    # care about.
    af.PERMISSIVE = (mode == "default")

    p1, p2 = _free_port(), _free_port()
    r1_base = "http://127.0.0.1:%d" % p1
    r2_base = "http://127.0.0.1:%d" % p2
    s1, s2 = _serve(p1), _serve(p2)
    try:
        _wait(p1)
        _wait(p2)
        print("resource one (authorization side): %s/mcp" % r1_base)
        print("resource two (%s mode)           : %s/mcp" % (mode, r2_base))

        token = _mint(r1_base, r1_base + "/mcp")   # aud = resource one
        print("minted a token for resource one (aud=%s/mcp)" % r1_base)

        status = _present(r2_base, token)          # present it to resource two
        print("presented it to resource two -> HTTP %d" % status)

        if 200 <= status < 300:
            print("VERDICT: FOREIGN ACCEPTED  (resource two honoured a token minted for resource one)")
            return 1
        if status in (401, 403):
            print("VERDICT: FOREIGN REFUSED  (resource two rejected a token minted for resource one)")
            return 0
        print("VERDICT: INCONCLUSIVE  (unexpected HTTP %d from resource two)" % status)
        return 2
    finally:
        s1.shutdown()
        s2.shutdown()


def main(argv):
    mode = argv[1] if len(argv) > 1 else "default"
    if mode not in ("default", "strict"):
        print("usage: python3 fixturepair.py [default|strict]", file=sys.stderr)
        return 2
    return run(mode)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
