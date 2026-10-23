"""Algorithm-confusion check: fires on an unverified-signature server, stays
clean on a hardened one.

CONTRIBUTING.md asks for two things a new check must satisfy: prove the
condition without weaponizing it, and come with a regression test that fires on
a vulnerable local fixture and stays clean on a hardened one. Both fixtures are
loopback-only.

The weaponized form of this class - signing an HS256 token with the target's
RSA public key - is deliberately not implemented. The check only sends tokens
whose signature segment is empty, which is enough to observe whether signatures
are verified at all. `assert_unsigned_only` below enforces that against the
fixture's own request log.
"""
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from jwt_weakness.extended_detector import ExtendedJWTDetector

PROBED_PATHS = ("/gateways", "/admin", "/api")


class _Fixture(BaseHTTPRequestHandler):
    """Serves the probed paths; subclasses decide what counts as authorized."""

    seen_tokens = []

    def do_GET(self):  # noqa: N802 - stdlib naming
        auth = self.headers.get("Authorization", "")
        token = auth[len("Bearer "):] if auth.startswith("Bearer ") else ""
        if token:
            type(self).seen_tokens.append(token)
        authorized = bool(token) and self.path in PROBED_PATHS and self._accepts(token)
        if authorized:
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _accepts(self, token):  # pragma: no cover - overridden
        return False

    def log_message(self, *args):
        pass


class _NoSignatureVerification(_Fixture):
    """Vulnerable: accepts any token whose signature segment is empty."""

    def _accepts(self, token):
        return token.endswith(".")


class _VerifiesSignatures(_Fixture):
    """Hardened: nothing unsigned is accepted."""

    def _accepts(self, token):
        return False


@pytest.fixture()
def serve(request):
    handler = request.param
    handler.seen_tokens = []
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", handler
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _header(token):
    head = token.split(".")[0]
    head += "=" * (-len(head) % 4)
    return json.loads(base64.urlsafe_b64decode(head.encode()).decode())


@pytest.mark.parametrize("serve", [_NoSignatureVerification], indirect=True)
def test_fires_when_signature_is_not_verified(serve):
    url, handler = serve
    findings = ExtendedJWTDetector(url, timeout=2).check_algorithm_confusion()

    assert findings, "no finding against a server that accepts unsigned tokens"
    assert all(f["type"] == "ALGORITHM_CONFUSION" for f in findings)
    variants = {f["variant"] for f in findings}
    assert variants == {"unsigned_none", "unsigned_hs256"}
    assert handler.seen_tokens, "the check sent no probe at all"


@pytest.mark.parametrize("serve", [_VerifiesSignatures], indirect=True)
def test_stays_clean_when_signatures_are_verified(serve):
    url, _handler = serve
    assert ExtendedJWTDetector(url, timeout=2).check_algorithm_confusion() == []


@pytest.mark.parametrize("serve", [_NoSignatureVerification], indirect=True)
def test_never_sends_a_signed_token(serve):
    """The probe must not forge a signature, even when the server would accept one."""
    url, handler = serve
    ExtendedJWTDetector(url, timeout=2).check_algorithm_confusion()

    assert handler.seen_tokens, "expected probes"
    for token in handler.seen_tokens:
        assert token.endswith("."), (
            f"a signed token was sent: {token[-16:]!r}; the check must stay unsigned"
        )
        assert _header(token)["alg"] in ("none", "HS256")
