"""Isolated HTTPS fixtures for Deployment Acknowledgment Proof tests.

Everything is local and ephemeral: a throwaway CA and leaf certificate generated per
test session, a TLS server bound to 127.0.0.1:0, and a resolver that answers only the
synthetic name ``dap.test`` (anything else raises, so no test can reach the network).
"""
import contextlib
import datetime
import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

FIXTURE_HOST = "dap.test"
PUBLICATION_PATH = "/.well-known/mcp-authscan-challenge"


def _name(common):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _cert(subject, issuer, public_key, signer, *, ca, sans=()):
    """Sign a certificate with the SKI/AKI, KeyUsage and EKU that strict OpenSSL chains require.

    The AKI is derived from ``signer``'s public key, so a leaf's AKI names its issuing CA and a
    self-signed CA's AKI equals its own SKI.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public_key).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=5))
               .not_valid_after(now + datetime.timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
                              critical=False))
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False),
            critical=True)
    else:
        builder = (builder
                   .add_extension(
                       x509.KeyUsage(digital_signature=True, key_cert_sign=False, crl_sign=False,
                                     content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False,
                                     encipher_only=False, decipher_only=False),
                       critical=True)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    return builder.sign(signer, hashes.SHA256())


def _ca(common):
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _cert(_name(common), _name(common), key.public_key(), key, ca=True)


def make_pki(directory):
    """Write ca.pem, leaf.pem/leaf.key (signed by the trusted CA) and rogue.pem/rogue.key.

    The rogue leaf carries the same names but is signed by a separate, untrusted CA that is
    never written to disk, so clients trusting only ca.pem must reject it.
    """
    sans = (x509.DNSName(FIXTURE_HOST), x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    ca_key, ca = _ca("dap-fixture-ca")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _cert(_name(FIXTURE_HOST), ca.subject, leaf_key.public_key(), ca_key, ca=False, sans=sans)
    rogue_ca_key, rogue_ca = _ca("dap-fixture-rogue-ca")
    rogue_key = ec.generate_private_key(ec.SECP256R1())
    rogue = _cert(_name(FIXTURE_HOST), rogue_ca.subject, rogue_key.public_key(), rogue_ca_key,
                  ca=False, sans=sans)
    paths = {}
    for name, data in (("ca.pem", ca.public_bytes(serialization.Encoding.PEM)),
                       ("leaf.pem", leaf.public_bytes(serialization.Encoding.PEM)),
                       ("leaf.key", _pem_key(leaf_key)),
                       ("rogue.pem", rogue.public_bytes(serialization.Encoding.PEM)),
                       ("rogue.key", _pem_key(rogue_key))):
        path = directory / name
        path.write_bytes(data)
        paths[name] = str(path)
    return paths


class FixtureState:
    """What the fixture serves and what it saw. ``routes`` maps a path to a callable(handler)."""

    def __init__(self):
        self.routes = {}
        self.requests = []
        self.lock = threading.Lock()
        # When set, POST /mcp answers 401 unless "Authorization: Bearer <mcp_token>".
        self.mcp_token = None

    def paths_seen(self):
        with self.lock:
            return [r["path"] for r in self.requests]


def text_reply(body, status=200, content_type="text/plain", headers=None):
    data = body.encode() if isinstance(body, str) else body

    def reply(handler):
        handler.send_response(status)
        handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(data)
    return reply


def slow_reply(delay, body):
    def reply(handler):
        time.sleep(delay)
        text_reply(body)(handler)
    return reply


def unbounded_reply(size):
    """A body far beyond the cap with no Content-Length, so only the read cap can stop it."""
    def reply(handler):
        handler.send_response(200)
        handler.send_header("Content-Type", "text/plain")
        handler.send_header("Connection", "close")
        handler.end_headers()
        try:
            handler.wfile.write(b"a" * size)
        except OSError:
            pass
    return reply


def mcp_reply(handler, raw):
    req = json.loads(raw or b"{}")
    method = req.get("method")
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "dap-fixture", "version": "1.0"}}
    elif method == "tools/list":
        result = {"tools": []}
    elif method == "notifications/initialized":
        return text_reply(b"", status=202, content_type="application/json")(handler)
    else:
        body = {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "Method not found"}}
        return text_reply(json.dumps(body), content_type="application/json")(handler)
    body = {"jsonrpc": "2.0", "id": req.get("id"), "result": result}
    return text_reply(json.dumps(body), content_type="application/json")(handler)


def _handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def _record(self):
            with state.lock:
                state.requests.append({"method": self.command, "path": self.path,
                                       "headers": {k.lower(): v for k, v in self.headers.items()}})

        def do_GET(self):
            self._record()
            route = state.routes.get(self.path)
            if route is None:
                return text_reply(b"not found", status=404)(self)
            return route(self)

        def do_POST(self):
            self._record()
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            if self.path == "/mcp":
                if state.mcp_token is not None and self.headers.get("Authorization") != "Bearer " + state.mcp_token:
                    return text_reply(b"", status=401, content_type="application/json",
                                      headers={"WWW-Authenticate": 'Bearer realm="dap-fixture"'})(self)
                return mcp_reply(self, raw)
            return text_reply(b"not found", status=404)(self)

    return Handler


@contextlib.contextmanager
def tls_server(certfile, keyfile, state):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(state))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile, keyfile)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.daemon_threads = True
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


class Resolver:
    """socket.getaddrinfo replacement: answers only for FIXTURE_HOST and numeric loopback.

    ``answers`` is a list of address lists consumed one per lookup of FIXTURE_HOST; the
    last entry repeats. Every other name raises gaierror, so nothing leaves the host.
    """

    def __init__(self, real, answers):
        self.real = real
        self.answers = list(answers)
        self.lookups = 0

    def __call__(self, host, port, *args, **kwargs):
        if host == FIXTURE_HOST:
            addresses = self.answers[min(self.lookups, len(self.answers) - 1)]
            self.lookups += 1
            family = kwargs.get("type", socket.SOCK_STREAM)
            return [(socket.AF_INET6 if ":" in a else socket.AF_INET, family, 6, "", (a, port))
                    for a in addresses]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            raise socket.gaierror(socket.EAI_NONAME, "fixture resolver: no external lookups") from None
        return self.real(host, port, *args, **kwargs)
