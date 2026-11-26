"""Issuer-binding check for the official Python MCP SDK client (package `mcp`).

Does the SDK's OAuthClientProvider refuse to send credentials that were registered
against one issuer when the server it now faces presents a different issuer?

SEP-2352: the provider binds stored client credentials to the issuer that registered
them and, per the provider source, decides this BEFORE fetching metadata --
_expected_issuer() is context.auth_server_url or the origin of server_url, and
credentials_match_issuer() compares the stored client_info.issuer against it.

The mismatch is created by pre-seeding storage with a client_info whose issuer is a
different string than the decoy's own origin. Consistent mode seeds the decoy origin,
so nothing is refused.

Reuses the decoy and helpers from run_issuer_binding.py. Drives `mcp`, never fastmcp.
Standard library + mcp only. Both modes exit 0 and print one JSON row each.
"""
import asyncio
import http.server
import json
import socket
import threading

from run_issuer_binding import (
    start_decoy, stop_decoy, redact, credential_present, Handler,
)

from mcp import Client
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientMetadata, OAuthClientInformationFull


# The decoy's Handler has no /register route; the SDK provider attempts dynamic client
# registration. We add it in a local subclass so the shared Handler is untouched. We also
# answer OPTIONS so a provider preflight never 404s. Everything else (GET metadata, 401 on
# /mcp, POST /token capture) is inherited unchanged.
class SDKHandler(Handler):
    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/register":
            self.server.touches.append("POST " + self.path)
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)  # registration is not a credential POST
            base = self.server.base_url
            return self.reply(201, {
                "client_id": "decoy-registered-client",
                "client_secret": "decoy-registered-secret",
                "redirect_uris": [base + "/callback"],
                "token_endpoint_auth_method": "client_secret_post",
            })
        return super().do_POST()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


def start_sdk_decoy():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SDKHandler)
    server.captured = []
    server.touches = []
    server.base_url = "http://127.0.0.1:%d" % server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def free_loopback_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class MemoryStorage(TokenStorage):
    """In-memory TokenStorage for one run, optionally pre-seeded with a client_info."""
    def __init__(self, client_info=None):
        self._tokens = None
        self._client_info = client_info

    async def get_tokens(self):
        return self._tokens

    async def set_tokens(self, tokens):
        self._tokens = tokens

    async def get_client_info(self):
        return self._client_info

    async def set_client_info(self, client_info):
        self._client_info = client_info


def seeded_client_info(redirect_uri, issuer):
    info = OAuthClientInformationFull(
        client_id="seeded-client",
        client_secret="seeded-secret",
        redirect_uris=[redirect_uri],
        token_endpoint_auth_method="client_secret_post",
    )
    info.issuer = issuer  # the field credentials_match_issuer() reads
    return info


async def run_mode(mode):
    assert mode in ("consistent", "mismatch")
    server = start_sdk_decoy()
    base = server.base_url
    recorded = {"authorize_url": None}

    try:
        cb_port = free_loopback_port()
        redirect_uri = "http://127.0.0.1:%d/callback" % cb_port

        if mode == "consistent":
            bound_issuer = base
        else:
            bound_issuer = "http://127.0.0.1:1/"  # a loopback origin the decoy is not served from

        storage = MemoryStorage(client_info=seeded_client_info(redirect_uri, bound_issuer))

        async def redirect_handler(authorization_url):
            recorded["authorize_url"] = authorization_url

        async def callback_handler():
            return ("decoy-code", None)

        # Provider built INSIDE the coroutine run by asyncio.run (not at import, not before
        # the loop) -- building it earlier is what caused the lock error before.
        provider = OAuthClientProvider(
            server_url=base + "/mcp",
            client_metadata=OAuthClientMetadata(
                client_name="mcp-authscan issuer-binding SDK probe",
                redirect_uris=[redirect_uri],
                grant_types=["authorization_code", "refresh_token"],
                token_endpoint_auth_method="client_secret_post",
            ),
            storage=storage,
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
            timeout=30.0,
        )

        verdict, reason = None, None
        try:
            async with streamablehttp_client(base + "/mcp", auth=provider) as (read, write, _):
                async with Client(read, write) as client:
                    await client.initialize()
                    await client.list_tools()
            cred = credential_present(server.captured)
            if cred:
                verdict = "FAIL"
                reason = "credential (%s) reached the decoy token endpoint" % cred
            else:
                verdict = "PASS"
                reason = "connected with no credential-bearing POST to the token endpoint"
        except Exception as exc:
            first = str(exc).splitlines()[0] if str(exc) else "(no message)"
            cred = credential_present(server.captured)
            if cred:
                verdict = "FAIL"
                reason = "credential (%s) reached the token endpoint before the flow ended (%s)" % (
                    cred, type(exc).__name__)
            elif recorded["authorize_url"] is None and not any(
                    t.startswith("POST /token") for t in server.touches):
                verdict = "PASS" if mode == "mismatch" else "EXCLUDED"
                reason = "provider stopped before sending credentials: %s: %s" % (
                    type(exc).__name__, first)
            else:
                verdict = "EXCLUDED"
                reason = "flow ended before a credential decision: %s: %s" % (
                    type(exc).__name__, first)

        evidence = []
        for e in server.captured:
            evidence.append({
                "path": e.get("path"),
                "authorization": redact(e.get("authorization")),
                "body_keys": sorted((e.get("body") or {}).keys()),
            })

        return {
            "client": "mcp-sdk %s" % _sdk_version(),
            "mode": mode,
            "verdict": verdict,
            "authorize_url": recorded["authorize_url"],
            "evidence": evidence,
            "reason": reason,
        }
    finally:
        stop_decoy(server)


def _sdk_version():
    try:
        import importlib.metadata as m
        return m.version("mcp")
    except Exception:
        return "unknown"


def main():
    for mode in ("consistent", "mismatch"):
        try:
            row = asyncio.run(run_mode(mode))
        except Exception as exc:
            first = str(exc).splitlines()[0] if str(exc) else "(no message)"
            row = {
                "client": "mcp-sdk %s" % _sdk_version(),
                "mode": mode,
                "verdict": "EXCLUDED",
                "authorize_url": None,
                "evidence": [],
                "reason": "harness could not run this mode: %s: %s" % (type(exc).__name__, first),
            }
        print(json.dumps(row))


if __name__ == "__main__":
    main()
