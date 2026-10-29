import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"
ISSUER = BASE + ("/" if os.environ.get("TRAILING_SLASH") == "1" else "")
MISBEHAVE = os.environ.get("MISBEHAVE") == "1"

# Registered client for success path
REGISTERED_CLIENT = "fixture-client"
REGISTERED_SECRET = "fixture-secret"

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

    def do_GET(self):
        p = self.path.split("?")[0]
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

        if p == "/token":
            form = dict(x.split("=", 1) for x in body.decode(errors="ignore").split("&") if "=" in x)
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
            return self._s(201, {"client_id": "test-client",
                                 "redirect_uris": [f"{BASE}/cb"],
                                 "token_endpoint_auth_method": "none"})
        return self._s(404, {"error": "not_found"})

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print("issuer=" + ISSUER + " misbehave=" + str(MISBEHAVE))
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
