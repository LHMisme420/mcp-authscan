import asyncio
import http.server
import json
import sys
import threading
from urllib.parse import parse_qs

DECOY_ISSUER = "https://decoy.invalid"
EXPECTED_ISSUER = "https://expected.invalid"
SECRET_KEYS = ("client_secret", "client_assertion", "assertion", "refresh_token")


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.touches.append(self.path)
        base = self.server.base_url
        if self.path.startswith("/.well-known/oauth-protected-resource"):
            return self.reply(200, {
                "resource": base + "/mcp",
                "authorization_servers": [base],
            })
        if self.path.startswith("/.well-known/oauth-authorization-server"):
            return self.reply(200, {
                "issuer": base,
                "token_endpoint": base + "/token",
                "authorization_endpoint": base + "/authorize",
                "registration_endpoint": base + "/register",
            })
        if self.path.startswith("/mcp"):
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % base,
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        self.server.touches.append("POST " + self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        self.server.captured.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "body": parse_qs(raw),
        })
        if path == "/token":
            return self.reply(200, {"access_token": "decoy-token", "token_type": "Bearer"})
        if path == "/mcp":
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % self.server.base_url)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return None
        return self.reply(404, {"error": "not_found"})


    def reply(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_decoy():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.captured = []
    server.touches = []
    server.base_url = "http://127.0.0.1:%d" % server.server_port
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop_decoy(server):
    server.shutdown()
    server.server_close()


def redact(value):
    if not value:
        return value
    text = str(value)
    if len(text) <= 8:
        return "***"
    return text[:4] + "..." + text[-4:]


def credential_present(captured):
    for entry in captured:
        if entry.get("authorization"):
            return "authorization header"
        for key in SECRET_KEYS:
            if (entry.get("body") or {}).get(key):
                return key
    return None


def provider_for(base_url, expect_issuer):
    from fastmcp.client.auth import ClientCredentialsOAuthProvider
    kwargs = {
        "client_id": "probe-client",
        "client_secret": "probe-secret",
    }
    if expect_issuer:
        kwargs["issuer"] = EXPECTED_ISSUER
    return ClientCredentialsOAuthProvider(base_url + "/mcp", **kwargs)


async def drive(provider, url):
    from fastmcp import Client
    async with Client(url + "/mcp", auth=provider) as client:
        await client.list_tools()


def run(expect_issuer):
    server = start_decoy()
    try:
        error = None
        try:
            provider = provider_for(server.base_url, expect_issuer)
        except Exception as exc:
            provider = None
            error = "provider construction failed: " + (str(exc) or "error")

        if provider is not None:
            try:
                asyncio.run(drive(provider, server.base_url))
            except Exception as exc:
                error = str(exc) or type(exc).name

        found = credential_present(server.captured)
        read_metadata = any("oauth-protected-resource" in t for t in server.touches)
        evidence = [
            {
                "path": entry.get("path"),
                "authorization": redact(entry.get("authorization")),
                "body_keys": sorted((entry.get("body") or {}).keys()),
            }
            for entry in server.captured
        ]

        if found:
            verdict = "FAIL"
            reason = "client presented credentials to an authorization server whose issuer did not match the protected resource"
        elif not read_metadata:
            verdict = "EXCLUDED"
            reason = "client never read the decoy metadata, so issuer binding was not exercised" + (": " + error if error else "")
        else:
            verdict = "PASS"
            reason = "client read the decoy metadata and presented no credential" + (": " + error if error else "")

        print("mode:", "expect-issuer" if expect_issuer else "default")
        print("verdict:", verdict)
        print("reason:", reason)
        print("touches:", server.touches)
        print("captured:", "none" if not evidence else "present")
        return verdict
    finally:
        stop_decoy(server)


try:
    if __name__ == "__main__":
        run("--expect-issuer" in sys.argv)
except Exception:
    import traceback
    traceback.print_exc()
    sys.exit(2)

