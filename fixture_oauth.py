import base64, hashlib, itertools, json, os, sys
from urllib.parse import urlsplit, parse_qs, urlencode
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"
ISSUER = BASE + ("/" if os.environ.get("TRAILING_SLASH") == "1" else "")
MISBEHAVE = os.environ.get("MISBEHAVE") == "1"

# Registered client for success path
REGISTERED_CLIENT = "fixture-client"
REGISTERED_SECRET = "fixture-secret"
REGISTERED_REDIRECT = f"{BASE}/cb"

# Authorization endpoint switches. Defaults are the secure behaviour.
#   PKCE_PLAIN=accept      code_challenge_method=plain is accepted (probe 7 FAIL branch)
#   REDIRECT_MATCH=prefix  any redirect_uri starting with the registered one is accepted (probe 8 FAIL branch)
PKCE_PLAIN_ACCEPT = os.environ.get("PKCE_PLAIN") == "accept"
REDIRECT_PREFIX = os.environ.get("REDIRECT_MATCH") == "prefix"

# Dynamic client registration (RFC 7591) and revocation switches. Defaults succeed.
#   REGISTRATION=fail  POST /register answers 400 invalid_client_metadata (no client is created)
#   REVOCATION=fail    POST /revoke answers 503 temporarily_unavailable (nothing is revoked)
#   REVOCATION=auth    POST /revoke answers 401 invalid_client, WWW-Authenticate: Basic (client
#                      authentication the scanner does not have; nothing is revoked)
#   REVOCATION=absent  the metadata advertises no revocation_endpoint (POST /revoke still exists)
#   REDIRECT_HOSTS=h1,h2  POST /register answers 400 invalid_redirect_uri unless every redirect_uri
#                      host is in the list (e.g. "localhost", or "127.0.0.1" so the scanner's first
#                      candidate is refused and the second accepted; "none" refuses every host)
# A registered client is a public client (token_endpoint_auth_method none) whose redirect_uris
# are exactly the ones it asked for; /authorize accepts it like the static client. Each
# registration also returns a registration_access_token, so a test can check it never leaks.
REGISTRATION_FAIL = os.environ.get("REGISTRATION") == "fail"
REVOCATION_FAIL = os.environ.get("REVOCATION") == "fail"
REVOCATION_AUTH = os.environ.get("REVOCATION") == "auth"
REVOCATION_ABSENT = os.environ.get("REVOCATION") == "absent"
REDIRECT_HOSTS = [h for h in os.environ.get("REDIRECT_HOSTS", "").split(",") if h]
DCR_CLIENTS = {}   # client_id -> list of registered redirect_uris
_DCR_SEQ = itertools.count(1)
REVOKED = []       # one entry per accepted POST /revoke: {"client_id", "token_sent"}

# Token acquisition (authorization code + PKCE S256) switches, for token-cors acquired-token mode.
#   CONSENT=deny         a valid S256 authorization request is answered 302 redirect_uri?error=access_denied
#   CONSENT=interactive  a valid S256 authorization request is answered 200 with an HTML consent page
#                        that needs a human click: POST /authorize/approve with its request id and a
#                        non-empty passphrase then answers 302 redirect_uri?code=fixture-code&state=...
#   CONSENT=wrong-state     the 302 carries the code with state "fixture-tampered-state"
#   CONSENT=wrong-redirect  the 302 carries the code and state, to redirect_uri + "-elsewhere"
# The attended flow (the scanner prints the URL, a person pastes the address the browser landed on)
# is driven in tests by a harness acting as the browser: GET /_issued returns the last 302 Location
# from /authorize or /authorize/approve and every code_verifier seen at /token, so a test can paste
# the address and grep scanner output for the code and verifier.
#   TOKEN_CORS=none      (default) the token response carries no Access-Control-Allow-Origin
#   TOKEN_CORS=wildcard       Access-Control-Allow-Origin: *
#   TOKEN_CORS=wildcard-cred  Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true
#   TOKEN_CORS=echo           the request Origin echoed, with Access-Control-Allow-Credentials: true
# With CONSENT unset, a valid S256 request (any client) gets 302 redirect_uri?code=fixture-code, plus
# the state that was sent. The code is redeemable once, at POST /token with grant_type
# authorization_code, the same client_id and redirect_uri, and a code_verifier whose S256 is the
# challenge. The access token issued is "fixture-acquired-token-<n>" so a test can grep all
# scanner output for it. POST /revoke with that token revokes it (and leaves the client alone).
CONSENT = os.environ.get("CONSENT", "")
TOKEN_CORS = os.environ.get("TOKEN_CORS", "none")
PENDING_CODES = {}  # client_id -> {"redirect_uri", "challenge"} of its last S256 authorization
PENDING_CONSENT = {}  # request id -> (client_id, redirect_uri, challenge, state dict), CONSENT=interactive
LAST_REDIRECT = []    # Location of each code/error 302 from /authorize and /authorize/approve
VERIFIERS_SEEN = []   # every code_verifier received at /token
_TOKEN_SEQ = itertools.count(1)
ISSUED_TOKENS = []   # access and refresh tokens issued by the authorization_code grant
REVOKED_TOKENS = []  # those revoked through POST /revoke

# Every GET to a redirect target is counted. A scanner that never follows a
# Location leaves these at 0; GET /_hits reports them without counting itself.
LOCATION_HITS = {}

AS = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{BASE}/authorize",
    "token_endpoint": f"{BASE}/token",
    "registration_endpoint": f"{BASE}/register",
    "revocation_endpoint": f"{BASE}/revoke",
    "device_authorization_endpoint": f"{BASE}/device",
    "jwks_uri": f"{BASE}/jwks",
    "response_types_supported": ["code"],
    "grant_types_supported": ["authorization_code"],
    "code_challenge_methods_supported": ["S256"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
}

if REVOCATION_ABSENT:
    del AS["revocation_endpoint"]
# JWKS=absent: the metadata advertises no jwks_uri, as an opaque-token server such as FlowState
# (probe 5 EXCLUDED branch). GET /jwks still answers.
if os.environ.get("JWKS") == "absent":
    del AS["jwks_uri"]

RES = {"resource": BASE + "/mcp", "authorization_servers": [BASE]}

class H(BaseHTTPRequestHandler):
    def _s(self, c, b, x=None):
        r = json.dumps(b).encode()
        self.send_response(c)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(r)))
        for k, v in (x or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(r)

    def _redirect(self, location):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _authorize(self):
        q = {k: v[0] for k, v in parse_qs(urlsplit(self.path).query).items()}
        cid = q.get("client_id")
        if cid == REGISTERED_CLIENT:
            registered = REGISTERED_REDIRECT
        elif cid in DCR_CLIENTS:
            registered = DCR_CLIENTS[cid][0]
        else:
            return self._s(400, {"error": "invalid_request", "error_description": "unknown client_id"})
        if q.get("response_type") != "code":
            return self._s(400, {"error": "unsupported_response_type"})
        redirect = q.get("redirect_uri", registered)
        if redirect != registered and not (REDIRECT_PREFIX and redirect.startswith(registered)):
            # RFC 6749 4.1.2.1: never redirect to an unverified redirect_uri
            return self._s(400, {"error": "invalid_request",
                                 "error_description": "redirect_uri does not match the registered value"})
        sep = "&" if "?" in redirect else "?"
        if not q.get("code_challenge"):
            return self._redirect(redirect + sep + urlencode(
                {"error": "invalid_request", "error_description": "code_challenge required"}))
        method = q.get("code_challenge_method", "plain")
        if method == "plain" and not PKCE_PLAIN_ACCEPT:
            return self._s(400, {"error": "invalid_request",
                                 "error_description": "code_challenge_method plain is not supported"})
        if method not in ("S256", "plain"):
            return self._s(400, {"error": "invalid_request",
                                 "error_description": "unsupported code_challenge_method"})
        state = {"state": q["state"]} if "state" in q else {}
        if method == "S256":
            if CONSENT == "deny":
                LAST_REDIRECT.append(redirect + sep + urlencode({"error": "access_denied", **state}))
                return self._redirect(LAST_REDIRECT[-1])
            if CONSENT == "interactive":
                rid = "req-%d" % (len(PENDING_CONSENT) + 1)
                PENDING_CONSENT[rid] = (cid, redirect, q["code_challenge"], state)
                page = ("<!doctype html><title>Authorize</title><form method=post action=/authorize/approve>"
                        "<p>Allow %s to access your account?</p><input type=hidden name=request value=%s>"
                        "<input type=password name=passphrase><button>Approve</button></form>" % (cid, rid)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(page)))
                self.end_headers()
                return self.wfile.write(page)
            return self._issue_code(cid, redirect, q["code_challenge"], state)
        return self._redirect(redirect + sep + urlencode({"code": "fixture-code", **state}))

    def _issue_code(self, cid, redirect, challenge, state):
        """302 to redirect_uri with a redeemable fixture-code (S256), shaped by CONSENT."""
        PENDING_CODES[cid] = {"redirect_uri": redirect, "challenge": challenge}
        if CONSENT == "wrong-state":
            state = {"state": "fixture-tampered-state"}
        if CONSENT == "wrong-redirect":
            redirect = redirect + "-elsewhere"
        sep = "&" if "?" in redirect else "?"
        LAST_REDIRECT.append(redirect + sep + urlencode({"code": "fixture-code", **state}))
        return self._redirect(LAST_REDIRECT[-1])

    def _token_cors(self):
        if TOKEN_CORS == "wildcard":
            return {"Access-Control-Allow-Origin": "*"}
        if TOKEN_CORS == "wildcard-cred":
            return {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}
        if TOKEN_CORS == "echo" and self.headers.get("Origin"):
            return {"Access-Control-Allow-Origin": self.headers.get("Origin"),
                    "Access-Control-Allow-Credentials": "true"}
        return {}

    def _redeem_code(self, form):
        """authorization_code + PKCE S256 grant; None when the request is not one."""
        cid = form.get("client_id", "")
        pending = PENDING_CODES.get(cid)
        verifier = form.get("code_verifier", "")
        VERIFIERS_SEEN.append(verifier)
        if not (pending and form.get("code") == "fixture-code" and verifier):
            return None
        if cid == REGISTERED_CLIENT and form.get("client_secret") != REGISTERED_SECRET:
            return None
        if cid != REGISTERED_CLIENT and cid not in DCR_CLIENTS:
            return None
        if form.get("redirect_uri") != pending["redirect_uri"]:
            return None
        s256 = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if s256 != pending["challenge"]:
            return None
        del PENDING_CODES[cid]
        n = next(_TOKEN_SEQ)
        access, refresh = "fixture-acquired-token-%d" % n, "fixture-acquired-refresh-%d" % n
        ISSUED_TOKENS.extend([access, refresh])
        print("TOKEN issued to " + cid + " cors=" + TOKEN_CORS, file=sys.stderr, flush=True)
        return self._s(200, {"access_token": access, "token_type": "Bearer", "expires_in": 3600,
                             "refresh_token": refresh},
                       {"Cache-Control": "no-store", "Pragma": "no-cache", **self._token_cors()})

    def do_GET(self):
        p = self.path.split("?")[0]
        print("GET " + p, file=sys.stderr, flush=True)
        if p == "/authorize":
            return self._authorize()
        if p == "/_hits":
            return self._s(200, LOCATION_HITS)
        if p == "/_issued":
            # test harness only: what a browser would show in its address bar, and the verifiers seen
            return self._s(200, {"last_redirect": LAST_REDIRECT[-1] if LAST_REDIRECT else None,
                                 "verifiers": VERIFIERS_SEEN})
        if p == "/_clients":
            # registered (and not revoked) dynamic clients, without any credential
            return self._s(200, {"registered": sorted(DCR_CLIENTS), "revoked": REVOKED,
                                 "tokens_issued": len(ISSUED_TOKENS),
                                 "tokens_revoked": len(REVOKED_TOKENS),
                                 "tokens_outstanding": len(set(ISSUED_TOKENS) - set(REVOKED_TOKENS))})
        if p.startswith("/cb"):
            LOCATION_HITS[p] = LOCATION_HITS.get(p, 0) + 1
            print("LOCATION-HIT " + p, file=sys.stderr, flush=True)
            return self._s(200, {"redirect_target": p})
        if p in ("/.well-known/oauth-protected-resource/mcp",
                 "/.well-known/oauth-protected-resource",
                 "/resource_metadata"):
            return self._s(200, RES)
        if p == "/.well-known/oauth-authorization-server":
            return self._s(200, AS)
        if p == "/jwks":
            if os.environ.get("JWKS_HS") == "1":
                return self._s(200, {"keys": [{"kty": "oct", "kid": "hs1", "use": "sig", "alg": "HS256", "k": "c2VjcmV0"}]})
            return self._s(200, {"keys": [{"kty": "RSA", "kid": "t1", "use": "sig", "alg": "RS256", "n": "sXch0A", "e": "AQAB"}]})
        return self._s(404, {"error": "not_found"})

    def do_POST(self):
        p = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""

        if p in ("/mcp", "/initialize", "/", ""):
            return self._s(401, {"error": "unauthorized"},
                           {"WWW-Authenticate": f'Bearer resource_metadata="{BASE}/resource_metadata"'})

        if p == "/authorize/approve":
            form = {k: v[0] for k, v in parse_qs(body.decode(errors="ignore")).items()}
            pending = PENDING_CONSENT.get(form.get("request", ""))
            if pending is None or not form.get("passphrase"):
                # the consent page stays pending: a person can retry the passphrase
                return self._s(400, {"error": "access_denied", "error_description": "no pending request or passphrase"})
            del PENDING_CONSENT[form["request"]]
            print("CONSENT approved " + pending[0], file=sys.stderr, flush=True)
            return self._issue_code(*pending)

        if p == "/token":
            form = dict(x.split("=", 1) for x in body.decode(errors="ignore").split("&") if "=" in x)
            if form.get("grant_type") == "authorization_code" and "code_verifier" in form:
                redeemed = self._redeem_code({k: v[0] for k, v in parse_qs(body.decode(errors="ignore")).items()})
                if redeemed is not None:
                    return redeemed
            grant = form.get("grant_type", "")
            client_id = form.get("client_id", "")
            client_secret = form.get("client_secret", "")
            code = form.get("code", "")
            auth = self.headers.get("Authorization", "")
            has_basic = auth.lower().startswith("basic ")
            has_client = bool(client_id) or has_basic

            if MISBEHAVE:
                if grant == "client_credentials" and client_id == REGISTERED_CLIENT and client_secret == REGISTERED_SECRET:
                    cors = {"Access-Control-Allow-Credentials": "true"}
                    origin = self.headers.get("Origin")
                    if origin:
                        cors["Access-Control-Allow-Origin"] = origin
                    return self._s(200, {"access_token": "fixture-token", "token_type": "Bearer"},
                                   {"Cache-Control": "no-store", "Pragma": "no-cache", **cors})
                if grant == "password" and client_id == REGISTERED_CLIENT and client_secret == REGISTERED_SECRET:
                    return self._s(200, {"access_token": "fixture-password-token", "token_type": "Bearer"},
                                   {"Cache-Control": "no-store", "Pragma": "no-cache"})
                return self._s(400, {"error": "invalid_request"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache",
                                "Access-Control-Allow-Origin": "*",
                                "Access-Control-Allow-Credentials": "true"})

            # RFC 6749 5.2 error responses
            # 1. Missing client authentication → 401 invalid_client
            if not has_client:
                return self._s(401, {"error": "invalid_client"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache"})
            
            # 2. Unsupported grant type
            if grant == "password":
                return self._s(400, {"error": "unsupported_grant_type"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache"})
            
            # 3. Valid grant: authorization_code with registered client
            if grant == "authorization_code" and client_id == REGISTERED_CLIENT and client_secret == REGISTERED_SECRET:
                return self._s(200, {"access_token": "fixture-token", "token_type": "Bearer"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache"})
            
            # 3b. Valid grant: client_credentials with registered client
            if grant == "client_credentials" and client_id == REGISTERED_CLIENT and client_secret == REGISTERED_SECRET:
                return self._s(200, {"access_token": "fixture-token", "token_type": "Bearer"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache"})

            # 4. Invalid/missing required params
            if grant != "authorization_code":
                return self._s(400, {"error": "invalid_request"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache"})
            
            # 5. Bad authorization code or wrong client
            return self._s(400, {"error": "invalid_grant"},
                           {"Cache-Control": "no-store", "Pragma": "no-cache"})

        if p == "/register":
            if REGISTRATION_FAIL:
                print("REGISTER refused", file=sys.stderr, flush=True)
                return self._s(400, {"error": "invalid_client_metadata",
                                     "error_description": "registration disabled on this fixture"},
                               {"Cache-Control": "no-store"})
            try:
                meta = json.loads(body.decode() or "{}")
            except ValueError:
                return self._s(400, {"error": "invalid_client_metadata"})
            uris = meta.get("redirect_uris") if isinstance(meta, dict) else None
            if not (isinstance(uris, list) and uris and all(isinstance(u, str) for u in uris)):
                return self._s(400, {"error": "invalid_redirect_uri"})
            if REDIRECT_HOSTS and any(urlsplit(u).hostname not in REDIRECT_HOSTS for u in uris):
                print("REGISTER refused redirect " + " ".join(uris), file=sys.stderr, flush=True)
                return self._s(400, {"error": "invalid_redirect_uri",
                                     "error_description": "redirect URI host is not on the allow-list"},
                               {"Cache-Control": "no-store"})
            cid = "dcr-client-%d" % next(_DCR_SEQ)
            DCR_CLIENTS[cid] = list(uris)
            print("REGISTER " + cid + " " + " ".join(uris), file=sys.stderr, flush=True)
            return self._s(201, {"client_id": cid,
                                 "redirect_uris": list(uris),
                                 "grant_types": ["authorization_code"],
                                 "response_types": ["code"],
                                 "token_endpoint_auth_method": "none",
                                 "registration_access_token": "fixture-rat-" + cid},
                           {"Cache-Control": "no-store"})

        if p == "/revoke":
            form = {k: v[0] for k, v in parse_qs(body.decode(errors="ignore")).items()}
            if REVOCATION_FAIL:
                print("REVOKE refused " + form.get("client_id", ""), file=sys.stderr, flush=True)
                return self._s(503, {"error": "temporarily_unavailable"})
            if REVOCATION_AUTH:
                print("REVOKE unauthenticated " + form.get("client_id", ""), file=sys.stderr, flush=True)
                return self._s(401, {"error": "invalid_client"}, {"WWW-Authenticate": 'Basic realm="fixture"'})
            cid = form.get("client_id", "")
            if form.get("token") in ISSUED_TOKENS:
                # token revocation (RFC 7009): the token is revoked, the client stays registered
                REVOKED_TOKENS.append(form["token"])
                print("REVOKE token of " + cid, file=sys.stderr, flush=True)
                return self._s(200, {})
            DCR_CLIENTS.pop(cid, None)
            REVOKED.append({"client_id": cid, "token_sent": bool(form.get("token"))})
            print("REVOKE " + cid, file=sys.stderr, flush=True)
            return self._s(200, {})
        return self._s(404, {"error": "not_found"})

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print("issuer=" + ISSUER + " misbehave=" + str(MISBEHAVE)
          + " pkce_plain=" + ("accept" if PKCE_PLAIN_ACCEPT else "refuse")
          + " redirect_match=" + ("prefix" if REDIRECT_PREFIX else "exact")
          + " registration=" + ("fail" if REGISTRATION_FAIL else "ok")
          + " revocation=" + (os.environ.get("REVOCATION") or "ok")
          + " redirect_hosts=" + (",".join(REDIRECT_HOSTS) or "any")
          + " consent=" + (CONSENT or "auto") + " token_cors=" + TOKEN_CORS, flush=True)
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
