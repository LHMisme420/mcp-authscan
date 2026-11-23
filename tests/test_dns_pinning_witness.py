"""Independent socket, DNS, Host, TLS and deadline witnesses."""
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import Request

import pytest

from mcp_authscan import monolith, oauth_probes_v2 as oauth
from mcp_authscan.errors import EgressRefusalError


HOST = "fixture.example.test"
PUBLIC = "93.184.216.34"


class Handler(BaseHTTPRequestHandler):
    received_hosts = []
    def do_GET(self):
        type(self).received_hosts.append(self.headers.get("Host"))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/trickle":
            self.send_response(200)
            self.send_header("Content-Length", "20")
            self.end_headers()
            for _ in range(20):
                try:
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(.15)
                except (BrokenPipeError, ConnectionResetError):
                    break
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")

    def log_message(self, *args):
        pass


@pytest.fixture
def server():
    Handler.received_hosts = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def witnesses(port):
    seen = {"dns": 0, "connections": []}

    def dns(name, target_port, *args, **kwargs):
        seen["dns"] += 1
        ip = PUBLIC if seen["dns"] == 1 else "127.0.0.1"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, target_port))]

    def connect(address, *args, **kwargs):
        seen["connections"].append(address)
        assert address == (PUBLIC, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))
        return sock

    return seen, dns, connect


def test_socket_pin_dns_rebinding_and_received_host(server):
    port = server.server_address[1]
    seen, dns, connect = witnesses(port)

    with patch.object(socket, "getaddrinfo", side_effect=dns), \
         patch.object(socket, "create_connection", side_effect=connect):
        status, _, body = oauth._egress_guard(
            Request(f"http://{HOST}:{port}/"),
            timeout=5,
            allow_private=False,
            allowed_hosts={HOST},
        )

    print("PINNED_SOCKET_ADDRESS:", seen["connections"])
    print("DNS_LOOKUP_COUNT:", seen["dns"])
    print("FIXTURE_RECEIVED_HOST:", Handler.received_hosts)

    assert status == 200 and body == b"OK"
    assert seen["connections"] == [(PUBLIC, port)]
    assert seen["dns"] == 1
    assert Handler.received_hosts == [f"{HOST}:{port}"]


def test_default_private_and_mixed_dns_denied_before_connection():
    assert monolith.ALLOW_PRIVATE_TARGETS is False
    print("DEFAULT_ALLOW_PRIVATE:", monolith.ALLOW_PRIVATE_TARGETS)

    cases = {
        "IPv4_LOOPBACK": ["127.0.0.1"],
        "IPv6_LOOPBACK": ["::1"],
        "MAPPED_METADATA": ["::ffff:169.254.169.254"],
        "CGNAT": ["100.64.0.1"],
        "BENCHMARK": ["198.18.0.1"],
        "ZERO_NETWORK": ["0.0.0.1"],
        "UNIQUE_LOCAL": ["fc00::1"],
        "LINK_LOCAL": ["fe80::1"],
        "MIXED_DNS": [PUBLIC, "127.0.0.1"],
    }

    for label, addresses in cases.items():
        connections = []
        def dns(name, port, *args, **kwargs):
            return [
                (socket.AF_INET6 if ":" in ip else socket.AF_INET,
                 socket.SOCK_STREAM, 6, "", (ip, port))
                for ip in addresses
            ]
        def connect(address, *args, **kwargs):
            connections.append(address)
            raise AssertionError("unsafe socket attempted")

        with patch.object(socket, "getaddrinfo", side_effect=dns), \
             patch.object(socket, "create_connection", side_effect=connect):
            with pytest.raises(EgressRefusalError) as error:
                oauth._egress_guard(
                    Request(f"https://{HOST}/"),
                    allow_private=False,
                    allowed_hosts={HOST},
                )

        assert not connections
        print(label, "REFUSED", str(error.value),
              "SOCKET_CONNECT_ATTEMPTS:", len(connections))


def test_redirect_has_fresh_pin_and_no_connection_reuse(server):
    port = server.server_address[1]
    seen = {"dns": 0, "connections": []}

    def dns(name, requested_port, *args, **kwargs):
        seen["dns"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (PUBLIC, requested_port))]

    def connect(address, *args, **kwargs):
        seen["connections"].append(address)
        assert address == (PUBLIC, port)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))
        return sock

    with patch.object(socket, "getaddrinfo", side_effect=dns), \
         patch.object(socket, "create_connection", side_effect=connect):
        status, _, body = oauth._egress_guard(
            Request(f"http://{HOST}:{port}/redirect"),
            allowed_hosts={HOST},
            allow_private=False,
        )

    print("REDIRECT_DNS_LOOKUPS:", seen["dns"])
    print("REDIRECT_SOCKET_CONNECTIONS:", seen["connections"])
    assert status == 200 and body == b"OK"
    assert seen["dns"] == 2
    assert seen["connections"] == [(PUBLIC, port), (PUBLIC, port)]


def test_server_observed_sni_and_hostname_mismatch():
    with tempfile.TemporaryDirectory() as directory:
        cert = Path(directory) / "cert.pem"
        key = Path(directory) / "key.pem"
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-nodes", "-days", "1",
            "-keyout", str(key), "-out", str(cert),
            "-subj", "/CN=wrong.example.test",
            "-addext", "subjectAltName=DNS:wrong.example.test",
        ], check=True, capture_output=True)

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        port = srv.server_address[1]
        seen_sni = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        context.set_servername_callback(
            lambda sock, name, ctx: seen_sni.append(name))
        srv.socket = context.wrap_socket(srv.socket, server_side=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()

        seen, dns, connect = witnesses(port)
        original_context = ssl.create_default_context

        def trusted_context(*args, **kwargs):
            ctx = original_context(*args, **kwargs)
            ctx.load_verify_locations(cafile=str(cert))
            return ctx

        try:
            with patch.object(socket, "getaddrinfo", side_effect=dns), \
                 patch.object(socket, "create_connection", side_effect=connect), \
                 patch.object(ssl, "create_default_context",
                              side_effect=trusted_context):
                with pytest.raises(URLError) as error:
                    oauth._egress_guard(
                        Request(f"https://{HOST}:{port}/"),
                        allowed_hosts={HOST},
                        allow_private=False,
                    )

            reason = error.value.reason
            print("PINNED_SOCKET_ADDRESS:", seen["connections"])
            print("DNS_LOOKUP_COUNT:", seen["dns"])
            print("FIXTURE_RECEIVED_SNI:", seen_sni or [None])
            print("TLS_MISMATCH_RESULT:", str(reason))

            assert isinstance(reason, ssl.SSLCertVerificationError)
            assert "hostname mismatch" in str(reason).lower()
            assert seen_sni == [HOST]
            assert seen["dns"] == 1
            assert seen["connections"] == [(PUBLIC, port)]
        finally:
            srv.shutdown()
            srv.server_close()


def test_total_deadline_stops_trickle(server):
    port = server.server_address[1]
    seen, _, connect = witnesses(port)

    def dns(name, requested_port, *args, **kwargs):
        seen["dns"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (PUBLIC, requested_port))]

    with patch.object(socket, "getaddrinfo", side_effect=dns), \
         patch.object(socket, "create_connection", side_effect=connect):
        start = time.monotonic()
        with pytest.raises((TimeoutError, EgressRefusalError, URLError)):
            oauth._egress_guard(
                Request(f"http://{HOST}:{port}/trickle"),
                timeout=.5,
                allowed_hosts={HOST},
                allow_private=False,
            )
        elapsed = time.monotonic() - start

    print("TRICKLE_ELAPSED_SECONDS:", round(elapsed, 3))
    assert elapsed < 1.5
