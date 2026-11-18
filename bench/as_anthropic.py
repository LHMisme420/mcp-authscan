"""Issuer-binding conformance decoy (mismatched mode), for observing an MCP OAuth
*client* that runs on someone else's servers and therefore cannot reach a loopback
decoy.

What this is for
----------------
A conformant OAuth client must validate the issuer in the authorization-server
metadata against the origin it fetched that metadata from (RFC 8414 / RFC 9207
mix-up defence) *before* it sends anything to the token endpoint. This server
advertises an issuer on a deliberately different host than the one serving the
document. If the client under test ever reaches ``POST /token`` here, it
transmitted before it compared — that single fact is the whole finding.

Operate it only against a client you are entitled to test — in practice a connector
you registered on your own account, pointed at a host you control. The only
credential that can arrive is one you issued to yourself.

Safety properties (enforced below, by construction)
---------------------------------------------------
- It records only: a timestamp, the request method and path, and the ``client_id``
  read from the public ``/authorize`` query string. It never reads or stores the
  ``Authorization`` header or the request body — so a client secret or an
  authorization code presented at ``/token`` is neither logged nor retained.
- It issues no tokens. ``/token`` answers ``400 invalid_client``. There is nothing
  here for anyone to replay; the finding ("the client transmitted") does not need a
  token to exist.
- This is the shape of mcp_authscan/decoy_auth_server.py (whose helpers it reuses),
  put into mismatched mode and made reachable, with capture and token issuance
  removed.

Run:
    AS_PUBLIC_BASE=https://host-you-control.example AS_ISSUER=https://issuer.example \
        python3 bench/as_anthropic.py
"""
import json
import os
import threading
import time
from http.server import ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, urlencode

from mcp_authscan.decoy_auth_server import Handler as DecoyHandler

# The origin that actually serves these documents (the operator's own public host,
# behind TLS termination). The client fetches metadata from here.
PUBLIC_BASE = os.environ.get("AS_PUBLIC_BASE", "http://127.0.0.1:8443").rstrip("/")
# The issuer advertised in the authorization-server document. Naming a *different*
# host than PUBLIC_BASE is the test: a client that enforces issuer binding refuses
# before the token request. Defaults to a non-resolving example host so the
# mismatch is structural and points at no real party.
ISSUER = os.environ.get("AS_ISSUER", "https://issuer.example").rstrip("/")


class AsAnthropic(DecoyHandler):
    """decoy_auth_server shape, mismatched issuer, record-only, no tokens."""

    def _record(self, event, client_id=None):
        # Arrival, path, client_id only. Never the Authorization header, never the
        # body. client_id is taken from the public /authorize query, not from a
        # token-endpoint credential.
        entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "event": event, "method": self.command, "path": self.path.split("?")[0]}
        if client_id is not None:
            entry["client_id"] = client_id
        self.server.observations.append(entry)
        print(json.dumps(entry), flush=True)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path.startswith("/.well-known/oauth-protected-resource"):
            # Exactly one entry in authorization_servers: the client reads the first.
            return self.reply(200, {
                "resource": PUBLIC_BASE + "/mcp",
                "authorization_servers": [PUBLIC_BASE],
            })
        if path.startswith("/.well-known/oauth-authorization-server"):
            # issuer names a different host than the one serving this document.
            return self.reply(200, {
                "issuer": ISSUER,
                "authorization_endpoint": PUBLIC_BASE + "/authorize",
                "token_endpoint": PUBLIC_BASE + "/token",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            })
        if path == "/authorize":
            q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
            self._record("authorize", client_id=q.get("client_id"))
            redirect_uri = q.get("redirect_uri")
            if not redirect_uri:
                return self.reply(400, {"error": "invalid_request"})
            params = {"code": "abc"}
            if "state" in q:
                params["state"] = q["state"]          # echo the incoming state
            sep = "&" if "?" in redirect_uri else "?"
            location = redirect_uri + sep + urlencode(params)
            self.send_response(302)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path.startswith("/mcp"):
            return self._unauthorized_mcp()
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/token":
            # Record that the client reached the token endpoint. Do not read the
            # Authorization header or the body: the finding is arrival, not content.
            self._record("token")
            return self.reply(400, {"error": "invalid_client"})
        if path.startswith("/mcp"):
            return self._unauthorized_mcp()
        return self.reply(404, {"error": "not_found"})


def main():
    server = ThreadingHTTPServer(("0.0.0.0", 8443), AsAnthropic)
    server.observations = []
    server.base_url = PUBLIC_BASE
    print("issuer-binding decoy (mismatched): serving %s, advertising issuer %s"
          % (PUBLIC_BASE, ISSUER), flush=True)
    print("records arrival/path/client_id only; no header, no body, no tokens", flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
