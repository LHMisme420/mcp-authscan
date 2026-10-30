#!/usr/bin/env python3
"""Test server: a complete OAuth authorization server on 9004 that satisfies every prerequisite
the probe set declares (PROBE_CONTRACT.md [1]-[9]). Confidential clients (client_secret_basic or client_secret_post; no credentials is 401),
PKCE S256 only, exact redirect_uri match, RFC 7591 registration, RFC 7009 revocation, RFC 7592
client deletion. Standard library only."""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlsplit, parse_qsl, quote, unquote_plus
import base64
import hashlib
import json
import secrets
import sys
import time

BASE = "http://127.0.0.1:9004"  # set from the port argument in __main__
# Token endpoint client authentication methods accepted at /token, /revoke and /device, and
# advertised in the metadata. The basic-only variant (test_fixture_basic_only_authserver.py)
# narrows this to client_secret_basic; 9004 accepts both.
ACCEPTED_AUTH_METHODS = ("client_secret_basic", "client_secret_post")

CLIENTS = {}   # client_id -> {"secret", "redirect_uris", "rat"}
CODES = {}     # code -> {"client_id", "redirect_uri", "challenge"}
TOKENS = set()


def _client_auth(headers, form):
    """client_id when the request authenticates the client by exactly one of client_secret_basic
    (RFC 6749 2.3.1 HTTP Basic) or client_secret_post (client_id and client_secret in the body).
    None when no credentials are present, they are wrong, or both methods are used at once."""
    auth = headers.get("Authorization", "")
    has_basic = auth.startswith("Basic ")
    has_post = "client_secret" in form
    if has_basic == has_post:
        return None
    if ("client_secret_basic" if has_basic else "client_secret_post") not in ACCEPTED_AUTH_METHODS:
        return None
    if has_basic:
        try:
            cid, _, secret = base64.b64decode(auth[6:]).decode("utf-8").partition(":")
            cid, secret = unquote_plus(cid), unquote_plus(secret)
        except Exception:
            return None
    else:
        cid, secret = form.get("client_id", ""), form.get("client_secret", "")
    c = CLIENTS.get(cid)
    if c is not None and secret and secrets.compare_digest(c["secret"], secret):
        return cid
    return None


class FullAuthServerHandler(BaseHTTPRequestHandler):
    def _json(self, status, doc, extra=None):
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _form(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
        return dict(parse_qsl(raw, keep_blank_values=True)), raw

    def _mcp_401(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer resource_metadata="%s/resource_metadata"' % BASE)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorize(self, params):
        """Authorization request: PKCE S256 required, exact registered redirect_uri."""
        c = CLIENTS.get(params.get("client_id", ""))
        if c is None:
            return self._json(400, {"error": "invalid_request", "error_description": "unknown client_id"})
        redirect_uri = params.get("redirect_uri")
        if redirect_uri not in c["redirect_uris"]:
            return self._json(400, {"error": "invalid_request",
                                    "error_description": "redirect_uri does not match a registered redirect_uri"})
        if params.get("response_type") != "code":
            return self._json(400, {"error": "unsupported_response_type"})
        if not params.get("code_challenge"):
            return self._json(400, {"error": "invalid_request", "error_description": "code_challenge required"})
        if params.get("code_challenge_method") != "S256":
            return self._json(400, {"error": "invalid_request",
                                    "error_description": "code_challenge_method must be S256"})
        code = secrets.token_urlsafe(24)
        CODES[code] = {"client_id": params["client_id"], "redirect_uri": redirect_uri,
                       "challenge": params["code_challenge"]}
        location = redirect_uri + "?code=" + quote(code)
        if params.get("state"):
            location += "&state=" + quote(params["state"])
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/mcp":
            self._mcp_401()
        elif path == "/resource_metadata":
            self._json(200, {"resource": BASE + "/mcp", "authorization_servers": [BASE]})
        elif path == "/.well-known/oauth-authorization-server":
            self._json(200, {
                "issuer": BASE,
                "authorization_endpoint": BASE + "/authorize",
                "token_endpoint": BASE + "/token",
                "registration_endpoint": BASE + "/register",
                "revocation_endpoint": BASE + "/revoke",
                "device_authorization_endpoint": BASE + "/device",
                "jwks_uri": BASE + "/jwks",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": list(ACCEPTED_AUTH_METHODS),
                "code_challenge_methods_supported": ["S256"],
            })
        elif path == "/jwks":
            n = base64.urlsafe_b64encode(hashlib.sha512(b"fixture-9004-modulus").digest() * 4).rstrip(b"=")
            self._json(200, {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture-9004",
                                       "n": n.decode(), "e": "AQAB"}]},
                       {"Cache-Control": "public, max-age=3600"})
        elif path == "/authorize":
            self._authorize(dict(parse_qsl(parts.query, keep_blank_values=True)))
        else:
            self._json(404, {"error": "not_found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/mcp":
            self._mcp_401()
        elif path == "/authorize":
            self._authorize(self._form()[0])
        elif path == "/register":
            n = int(self.headers.get("Content-Length") or 0)
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json(400, {"error": "invalid_client_metadata"})
            uris = req.get("redirect_uris")
            if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
                return self._json(400, {"error": "invalid_redirect_uri"})
            cid = "client-%s" % secrets.token_hex(6)
            secret, rat = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
            CLIENTS[cid] = {"secret": secret, "redirect_uris": list(uris), "rat": rat}
            self._json(201, {
                "client_id": cid,
                "client_secret": secret,
                "client_id_issued_at": int(time.time()),
                "client_secret_expires_at": 0,
                "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "redirect_uris": list(uris),
                "registration_access_token": rat,
                "registration_client_uri": BASE + "/register/" + cid,
            }, {"Cache-Control": "no-store"})
        elif path == "/token":
            form, _ = self._form()
            ns = {"Cache-Control": "no-store", "Pragma": "no-cache"}
            cid = _client_auth(self.headers, form)
            if cid is None:
                return self._json(401, {"error": "invalid_client"},
                                  dict(ns, **{"WWW-Authenticate": 'Basic realm="token"'}))
            grant = form.get("grant_type")
            if grant == "password":
                return self._json(400, {"error": "unsupported_grant_type"}, ns)
            if grant == "authorization_code":
                entry = CODES.pop(form.get("code", ""), None)
                verifier = form.get("code_verifier", "")
                expect = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                if (entry is None or entry["client_id"] != cid or entry["redirect_uri"] != form.get("redirect_uri")
                        or not verifier or expect != entry["challenge"]):
                    return self._json(400, {"error": "invalid_grant"}, ns)
                access, refresh = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
                TOKENS.update((access, refresh))
                return self._json(200, {"access_token": access, "token_type": "Bearer", "expires_in": 3600,
                                        "refresh_token": refresh}, ns)
            return self._json(400, {"error": "unsupported_grant_type"}, ns)
        elif path == "/revoke":
            form, _ = self._form()
            if _client_auth(self.headers, form) is None:
                return self._json(401, {"error": "invalid_client"}, {"WWW-Authenticate": 'Basic realm="revoke"'})
            TOKENS.discard(form.get("token", ""))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif path == "/device":
            form, _ = self._form()
            if _client_auth(self.headers, form) is None:
                return self._json(401, {"error": "invalid_client"}, {"WWW-Authenticate": 'Basic realm="device"'})
            self._json(400, {"error": "unauthorized_client"})
        else:
            self._json(404, {"error": "not_found"})

    def do_DELETE(self):
        path = urlsplit(self.path).path
        cid = path[len("/register/"):] if path.startswith("/register/") else None
        c = CLIENTS.get(cid) if cid else None
        if c is None:
            return self._json(404, {"error": "not_found"})
        auth = self.headers.get("Authorization", "")
        if not (auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], c["rat"])):
            return self._json(401, {"error": "invalid_token"}, {"WWW-Authenticate": "Bearer"})
        del CLIENTS[cid]
        self.send_response(204)
        self.end_headers()

    def log_message(self, format, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9004
    BASE = "http://127.0.0.1:%d" % port
    HTTPServer(("127.0.0.1", port), FullAuthServerHandler).serve_forever()
