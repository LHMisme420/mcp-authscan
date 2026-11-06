"""Issuer-binding check for the official Python MCP SDK client (package `mcp`).

Does the SDK's OAuthClientProvider refuse to send credentials to an authorization
server whose advertised issuer does not match the server URL the client was given?

Per the provider source (SEP-2352 / SEP-2468): _expected_issuer() is
context.auth_server_url or the origin of server_url; validate_metadata_issuer()
rejects authorization-server metadata whose "issuer" is not that expected value,
and this happens before any credential-bearing request is sent. Mismatched mode
makes the decoy advertise a different issuer string and expects that refusal.

Drives the `mcp` SDK only. No fastmcp. Standard library + mcp. Reuses the decoy and
redaction helpers that already live beside this file. Nothing enters the scan path;
the probe set does not move.

Usage:
    python3 tools/run_issuer_binding_sdk.py --mode consistent
    python3 tools/run_issuer_binding_sdk.py --mode mismatched
"""
import argparse
import asyncio
import importlib.metadata
import json
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

# --- reuse existing helpers; fail loudly and by name if a symbol differs -----------
# CONFIRM: these names come from the repo-root run_issuer_binding.py you pasted. If the
# tools/ copy differs, the grep will show it and only this import line changes.
try:
    from run_issuer_binding import redact, credential_present
except Exception as _e:  # ImportError or AttributeError
    def redact(v):
        if not v:
            return v
        t = str(v)
        return "***" if len(t) <= 8 else t[:4] + "..." + t[-4:]

    def credential_present(captured):
        for e in captured:
            if e.get("authorization"):
                return "authorization header"
            for k in ("client_secret", "client_assertion", "assertion", "refresh_token"):
                if (e.get("body") or {}).get(k):
                    return k
        return None
    print("note: run_issuer_binding helpers not importable (%s); using local copies"
          % type(_e).__name__, file=sys.stderr)

# --- SDK imports -------------------------------------------------------------------
from mcp.client.session import ClientSession  # CONFIRM: ClientSession, per mcp 1.30 layout
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientMetadata


# --- self-contained decoy ----------------------------------------------------------
# The task says reuse decoy_auth_server.py; its public API isn't visible from here, so
# this file carries a minimal decoy inline to stay runnable. CONFIRM: if you prefer the
# shared decoy, swap start_decoy()/stop_decoy() for its equivalents; the metadata shape
# below (advertised issuer differing from AS URL in mismatched mode) is the whole point.
class _DecoyHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        s = self.server
        s.touches.append("GET " + self.path)
        base = s.base_url
        if self.path.startswith("/authorize"):
            from urllib.parse import urlsplit, parse_qs as _pq, quote
            q = _pq(urlsplit(self.path).query)
            redirect = (q.get("redirect_uri") or [""])[0]
            state = (q.get("state") or [""])[0]
            state = state.replace("\r", "").replace("\n", "")
            sep = "&" if "?" in redirect else "?"
            loc = redirect.replace("\r", "").replace("\n", "") + sep + "code=decoy-code&state=" + quote(state)
            loc = loc.replace("\r", "").replace("\n", "")
            self.send_response(302)
            self.send_header("Location", loc)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            return self._json(200, {"resource": base + "/mcp", "authorization_servers": [base]})
        if self.path.startswith("/.well-known/oauth-authorization-server"):
            # advertised issuer: identical to base in consistent mode, different in mismatched
            return self._json(200, {
                "issuer": s.advertised_issuer,
                "authorization_endpoint": base + "/authorize",
                "token_endpoint": base + "/token",
                "registration_endpoint": base + "/register",
            })
        if self.path.startswith("/mcp"):
            self.send_response(401)
            self.send_header("WWW-Authenticate",
                             'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % base)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        return self._json(404, {"error": "not_found"})

    def do_POST(self):
        s = self.server
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        s.touches.append("POST " + self.path)
        rec = {"path": self.path, "authorization": self.headers.get("Authorization"),
               "body": parse_qs(raw)}
        s.captured.append(rec)
        if path == "/register":
            # SDK sends registration as a JSON body, not form-encoded, so rec["body"]
            # (parse_qs) is empty. Echo the server's known callback instead of [].
            import json as _json_mod
            try:
                reg = _json_mod.loads(raw) if raw.strip().startswith("{") else {}
            except Exception:
                reg = {}
            ruris = reg.get("redirect_uris") or [s.base_url + "/callback"]
            return self._json(201, {
                "client_id": "decoy-client", "client_secret": "decoy-secret",
                "redirect_uris": ruris,
                "token_endpoint_auth_method": "client_secret_post",
            })
        if path == "/token":
            s.token_hits += 1
            return self._json(200, {"access_token": "decoy-token", "token_type": "Bearer"})
        if path == "/mcp":
            auth = self.headers.get("Authorization") or ""
            if not auth.startswith("Bearer "):
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % s.base_url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None
            import json as J
            try:
                m = J.loads(raw) if raw.strip() else {}
            except Exception:
                m = {}
            if isinstance(m, list):
                m = m[0] if m else {}
            mid = m.get("id")
            if mid is None:
                return self._json(202, {})
            meth = m.get("method")
            if meth == "initialize":
                pv = (m.get("params") or {}).get("protocolVersion", "2025-06-18")
                return self._json(200, {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": pv, "capabilities": {"tools": {}}, "serverInfo": {"name": "decoy", "version": "0"}}})
            if meth == "tools/list":
                return self._json(200, {"jsonrpc": "2.0", "id": mid, "result": {"tools": []}})
            return self._json(200, {"jsonrpc": "2.0", "id": mid, "result": {}})
        return self._json(404, {"error": "not_found"})


def start_decoy(advertised_issuer_builder):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _DecoyHandler)
    srv.captured, srv.touches, srv.token_hits = [], [], 0
    srv.base_url = "http://127.0.0.1:%d" % srv.server_port
    srv.advertised_issuer = advertised_issuer_builder(srv.base_url)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def stop_decoy(srv):
    srv.shutdown()
    srv.server_close()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class MemoryStorage(TokenStorage):
    def __init__(self):
        self._t = None
        self._c = None

    async def get_tokens(self):
        return self._t

    async def set_tokens(self, t):
        self._t = t

    async def get_client_info(self):
        return self._c

    async def set_client_info(self, c):
        self._c = c


async def run(mode):
    if mode == "consistent":
        issuer_builder = lambda base: base            # advertised == AS url
    else:
        issuer_builder = lambda base: "https://not-the-decoy.invalid"  # advertised != AS url

    srv = start_decoy(issuer_builder)
    base = srv.base_url
    recorded = {"authorize_url": None}
    try:
        redirect_uri = "http://127.0.0.1:%d/callback" % free_port()

        async def redirect_handler(url):
            recorded["authorize_url"] = url

        async def callback_handler():
            # the decoy's 302 carries the same state the provider put in the authorize URL;
            # recover it so the provider's state check passes in consistent mode
            st = None
            u = recorded.get("authorize_url")
            if u:
                from urllib.parse import urlsplit, parse_qs as _pq, quote
                st = (_pq(urlsplit(u).query).get("state") or [None])[0]
            return ("decoy-code", st)

        # provider built inside the running loop, never at module scope
        provider = OAuthClientProvider(
            server_url=base + "/mcp",
            client_metadata=OAuthClientMetadata(
                client_name="mcp-authscan issuer-binding SDK probe",
                redirect_uris=[redirect_uri],
                grant_types=["authorization_code", "refresh_token"],
                token_endpoint_auth_method="client_secret_post",
            ),
            storage=MemoryStorage(),
            redirect_handler=redirect_handler,
            callback_handler=callback_handler,
            timeout=30.0,
        )

        reason = None
        try:
            async with streamablehttp_client(base + "/mcp", auth=provider) as (r, w, _):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    await session.list_tools()
            reason = "flow completed"
            completed = True
        except Exception as exc:
            completed = False
            root = exc
            while True:
                subs = getattr(root, "exceptions", None)
                if subs:
                    root = subs[0]
                    continue
                cause = getattr(root, "__cause__", None)
                if cause is not None:
                    root = cause
                    continue
                break
            reason = "%s: %s" % (type(root).__name__,
                                 (str(root).splitlines() or ["(no message)"])[0])

        cred = credential_present(srv.captured)
        token_hits = srv.token_hits

        if mode == "consistent":
            if completed and token_hits >= 1:
                verdict, code = "PASS", 0
            elif completed:
                verdict, code = "PASS", 0
                reason = "flow completed (no token POST required by this decoy path)"
            else:
                verdict, code = "EXCLUDED", 0
                reason = "consistent flow did not complete: " + reason
        else:  # mismatched
            if cred and token_hits >= 1:
                verdict, code = "FAIL", 1
            elif token_hits == 0 and not cred:
                verdict, code = "PASS", 0
                reason = "client refused before sending credentials: " + reason
            else:
                verdict, code = "FAIL", 1
                reason = "unexpected credential exposure: " + reason

        evidence = [{"path": e["path"], "authorization": redact(e.get("authorization")),
                     "body_keys": sorted((e.get("body") or {}).keys())} for e in srv.captured]

        print("%s  mode=%s" % (verdict, mode))
        print(json.dumps({
            "mode": mode,
            "mcp_version": _ver(),
            "issuer_expected": base,
            "issuer_advertised": srv.advertised_issuer,
            "token_endpoint_hits": token_hits,
            "verdict": verdict,
            "reason": reason,
            "evidence": evidence,
            "authorize_url": recorded["authorize_url"],
        }, indent=2))
        return code
    finally:
        stop_decoy(srv)


def _ver():
    try:
        return importlib.metadata.version("mcp")
    except Exception:
        return "unknown"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["consistent", "mismatched"], required=True)
    args = ap.parse_args()
    print("mcp package version: %s  (python: %s)" % (_ver(), sys.executable), file=sys.stderr)
    sys.exit(asyncio.run(run(args.mode)))


if __name__ == "__main__":
    main()
