import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", "8765"))
BASE = f"http://127.0.0.1:{PORT}"
ISSUER = BASE + ("/" if os.environ.get("TRAILING_SLASH") == "1" else "")

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
    "token_endpoint_auth_methods_supported": ["none"],
}

RES = {"resource": BASE, "authorization_servers": [BASE]}

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
        if p in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource", "/resource_metadata"):
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
        self._last_body = self.rfile.read(n) if n else b""
        
        if p in ("/mcp", "/initialize", "/", ""):
            return self._s(401, {"error": "unauthorized"}, {"WWW-Authenticate": f'Bearer resource_metadata="{BASE}/resource_metadata"'})
        
        if p == "/token":
            raw = getattr(self, "_last_body", b"")
            form = dict(x.split("=", 1) for x in raw.decode(errors='ignore').split("&") if "=" in x)
            grant = form.get("grant_type", "")

            if os.environ.get("MISBEHAVE") == "1":
                return self._s(200, {"access_token": "issued-without-client-auth", "token_type": "Bearer"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache",
                                "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})

            # clean mode: distinguish three requests
            if grant == "password":
                return self._s(400, {"error": "unsupported_grant_type"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache"})
            if grant == "invalid":
                # token-cors probe — must be 200 so ACAO is evaluated
                return self._s(200, {"error": "invalid_request"},
                               {"Cache-Control": "no-store", "Pragma": "no-cache",
                                "Access-Control-Allow-Origin": "https://allowed.example.com"})
            # authorization_code and others → client-auth PASS
            return self._s(400, {"error": "invalid_client"},
                           {"Cache-Control": "no-store", "Pragma": "no-cache",
                            "Access-Control-Allow-Origin": "https://allowed.example.com"})
        
        if p == "/register":
            return self._s(201, {"client_id": "test-client", "redirect_uris": [f"{BASE}/cb"], "token_endpoint_auth_method": "none"})
        
        return self._s(404, {"error": "not_found"})

    def do_OPTIONS(self):
        p = self.path.split("?")[0]
        if p == "/token":
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
            self.send_header("Access-Control-Max-Age", "86400")
            self.end_headers()
            return
        self.send_error(404)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    print("issuer=" + ISSUER)
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
