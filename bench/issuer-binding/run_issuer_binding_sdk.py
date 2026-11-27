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

import inspect
try:
    from mcp import Client  # mcp 2.x
except ImportError:  # mcp 1.x
    from mcp import ClientSession as Client
from mcp.client.streamable_http import create_mcp_http_client, streamable_http_client
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


_CLIENT_TAKES_TRANSPORT = "server" in inspect.signature(Client.__init__).parameters


def _flat(body):
    """Captured bodies come from parse_qs: each value is a list."""
    return {k: (v[0] if isinstance(v, list) and v else v) for k, v in (body or {}).items()}


def seeded_credential_present(captured):
    """The seeded (issuer-bound) credential reached the token endpoint. A secret the
    provider obtained by re-registering with this server is correct behaviour."""
    for entry in captured:
        body = _flat(entry.get("body"))
        if body.get("client_id") == "seeded-client" or body.get("client_secret") == "seeded-secret":
            return "seeded client_secret"
        auth = entry.get("authorization") or ""
        if auth and "seeded" in auth:
            return "seeded authorization header"
    return None


def _leaf(exc):
    while isinstance(exc, BaseExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def _make_provider(**kw):
    accepted = inspect.signature(OAuthClientProvider.__init__).parameters
    return OAuthClientProvider(**{k: v for k, v in kw.items() if k in accepted})


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
            # Echo the state the provider put in the authorization URL, as a real
            # redirect would; returning None trips the SDK's state check.
            from urllib.parse import parse_qs, urlsplit
            q = parse_qs(urlsplit(recorded["authorize_url"] or "").query)
            state = (q.get("state") or [None])[0]
            try:  # mcp 2.x returns a typed result, 1.x a (code, state) tuple
                from mcp.shared.auth import AuthorizationCodeResult
                return AuthorizationCodeResult(code="decoy-code", state=state)
            except ImportError:
                return ("decoy-code", state)

        # Provider built INSIDE the coroutine run by asyncio.run (not at import, not before
        # the loop) -- building it earlier is what caused the lock error before.
        provider = _make_provider(
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
            # streamable_http_client(url, http_client=...) exists in mcp 1.29+ and 2.x;
            # the yielded streams are a 3-tuple in 1.x and TransportStreams in 2.x.
            async with create_mcp_http_client(auth=provider) as http:
                transport = streamable_http_client(base + "/mcp", http_client=http)
                if _CLIENT_TAKES_TRANSPORT:  # mcp 2.x: Client(transport) connects itself
                    async with Client(transport) as client:
                        await client.list_tools()
                else:  # mcp 1.x: ClientSession(read, write)
                    async with transport as streams:
                        async with Client(streams[0], streams[1]) as client:
                            await client.initialize()
                            await client.list_tools()
            cred = seeded_credential_present(server.captured)
            if cred:
                verdict = "FAIL"
                reason = "credential (%s) reached the decoy token endpoint" % cred
            else:
                verdict = "PASS"
                reason = "connected with no credential-bearing POST to the token endpoint"
        except Exception as exc:
            exc = _leaf(exc)
            first = str(exc).splitlines()[0] if str(exc) else "(no message)"
            cred = seeded_credential_present(server.captured)
            if isinstance(exc, (TypeError, AttributeError, ImportError, NameError)):
                # A harness/API mismatch, not an OAuth decision: never score it PASS.
                verdict = "EXCLUDED"
                reason = "harness incompatible with this mcp version: %s: %s" % (type(exc).__name__, first)
            elif cred:
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

        ids = {str(_flat(e.get("body")).get("client_id") or "") for e in server.captured}
        seeded = seeded_credential_present(server.captured)
        if mode == "consistent" and seeded:
            # Control: the bound credential going to its own issuer is expected, not a finding.
            verdict, reason = "EXCLUDED", "control: the issuer-bound credential was presented to its own issuer, as expected"
        elif mode == "mismatch" and not seeded and "decoy-registered-client" in ids:
            verdict, reason = "PASS", ("discarded the credential bound to another issuer and re-registered with "
                                       "this server; the bound credential never reached the token endpoint")
        return {
            "client": "mcp-sdk %s" % _sdk_version(),
            "mode": mode,
            "token_client_ids": sorted({str(_flat(e.get("body")).get("client_id") or "") for e in server.captured}),
            "touches": list(server.touches),
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
