#!/usr/bin/env python3
"""End-to-end detection regression tests.

Each test binds a deliberately (mis)configured MCP-ish server to an ephemeral
loopback port, runs the real MCPScanner against it, and asserts the findings.

Positive fixtures confirm the CRITICAL/HIGH checks actually fire; the secure
fixture is a negative control that must stay clean (no false positives). All
traffic is loopback-only, so these need no network egress.
"""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp_authscan.cli import parse_headers
from mcp_authscan.scanner import MCPScanner, RiskLevel

# A JSON-RPC/MCP reply whose result carries sensitive data: the body is both
# "looks like an MCP endpoint" (has "jsonrpc") AND sensitive (access_token is a
# SECRET_FIELD in cors.py), so it drives the auth checks and the CORS check.
JSONRPC_BODY = json.dumps({
    "jsonrpc": "2.0", "id": 1,
    "result": {"tools": [], "account": {
        "email": "alice@example.com", "access_token": "sk-live-abc123xyz"}},
}).encode()
SSE_BODY = b"data: {\"jsonrpc\":\"2.0\"}\n\n"
HTML_BODY = b"<!doctype html><html><head><title>App</title></head><body>app</body></html>"
UNAUTH_BODY = b'{"error":"unauthorized"}'


def _make_handler(mode):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence per-request logging
            pass

        def _send(self, code, body=b"", headers=None):
            self.send_response(code)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # client (e.g. the streamed SSE probe) closed early

        def _dispatch(self):
            origin = self.headers.get("Origin")
            path = self.path.split("?", 1)[0]

            if mode == "secure":
                # Everything requires auth -> 401. Negative control.
                return self._send(401, UNAUTH_BODY, {
                    "Content-Type": "application/json", "WWW-Authenticate": "Bearer"})

            if mode == "spa-html":
                # SPA/docs catch-all: 200 text/html for every path & method.
                # This is NOT an MCP endpoint and must raise no findings.
                return self._send(200, HTML_BODY, {"Content-Type": "text/html; charset=utf-8"})

            if mode == "vuln-auth":
                # Zero-auth MCP server: real SSE stream + JSON-RPC replies to all.
                if path == "/sse":
                    return self._send(200, SSE_BODY, {"Content-Type": "text/event-stream"})
                return self._send(200, JSONRPC_BODY, {"Content-Type": "application/json"})

            if mode == "vuln-cors":
                # Only misbehave for the CORS probe (Origin present); plain auth
                # probes (no Origin) get 401 so those checks stay clean.
                if origin:
                    return self._send(200, JSONRPC_BODY, {
                        "Content-Type": "application/json",
                        "Access-Control-Allow-Origin": origin,       # reflects any origin
                        "Access-Control-Allow-Credentials": "true",  # -> HIGH severity
                    })
                return self._send(401, UNAUTH_BODY, {"Content-Type": "application/json"})

            return self._send(404)  # pragma: no cover

        do_GET = do_POST = do_HEAD = do_OPTIONS = _dispatch

    return Handler


class _MCPRealHandler(BaseHTTPRequestHandler):
    """Responds to any POST with a valid MCP initialize result."""

    def log_message(self, *args):
        pass

    def _dispatch(self):
        body = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "result": {"protocolVersion": "2025-06-18",
                       "serverInfo": {"name": "fixture-mcp", "version": "9.9"},
                       "capabilities": {}},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    do_GET = do_POST = do_HEAD = _dispatch


class FixtureServer:
    """Threaded loopback server bound to an ephemeral port."""

    def __init__(self, mode):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(mode))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        host, port = self.server.server_address[:2]
        self.url = f"http://{host}:{port}"
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def _by_name(checks, name):
    return [c for c in checks if c.name == name]


def _one(checks, name):
    matches = _by_name(checks, name)
    assert len(matches) == 1, f"expected exactly one {name!r}, got {len(matches)}"
    return matches[0]


class _HeaderRecorder(BaseHTTPRequestHandler):
    seen = []  # class-level sink for headers observed across requests

    def log_message(self, *args):
        pass

    def _dispatch(self):
        _HeaderRecorder.seen.append({k.lower(): v for k, v in self.headers.items()})
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_HEAD = do_OPTIONS = _dispatch


class HeaderOptionTests(unittest.TestCase):
    def test_parse_headers_valid_and_invalid(self):
        self.assertEqual(
            parse_headers(["X-Research: tag-123", "X-Foo:  bar "]),
            {"X-Research": "tag-123", "X-Foo": "bar"},
        )
        self.assertEqual(parse_headers([]), {})
        for bad in ["no-colon", ": empty-name"]:
            with self.assertRaises(ValueError):
                parse_headers([bad])

    def test_identifying_header_sent_on_every_request(self):
        _HeaderRecorder.seen = []
        server = ThreadingHTTPServer(("127.0.0.1", 0), _HeaderRecorder)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            MCPScanner(f"http://{host}:{port}", timeout=5,
                       headers={"X-HackerOne-Research": "researcher-42"}).scan()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.assertTrue(_HeaderRecorder.seen, "expected the scanner to send requests")
        self.assertTrue(
            all(h.get("x-hackerone-research") == "researcher-42"
                for h in _HeaderRecorder.seen),
            "identifying header must ride every probe, including the CORS probe",
        )


class FixtureDetectionTests(unittest.TestCase):
    def scan(self, mode):
        with FixtureServer(mode) as srv:
            return MCPScanner(srv.url, timeout=5).scan()

    def test_zero_auth_trips_critical_and_high(self):
        checks = self.scan("vuln-auth")
        for name in (
            "SSE Endpoint Authentication",
            "Message Endpoint Authentication",
            "MCP Endpoint Authentication",
        ):
            check = _one(checks, name)
            self.assertFalse(check.passed, f"{name} should fail on a zero-auth server")
            self.assertEqual(check.risk_level, RiskLevel.CRITICAL)

        fake_token = _one(checks, "Authorization Header Validation")
        self.assertFalse(fake_token.passed, "a fake bearer token should be rejected")
        self.assertEqual(fake_token.risk_level, RiskLevel.HIGH)

        # No Origin reflection -> CORS must NOT fire even though data is sensitive.
        self.assertTrue(all(c.passed for c in _by_name(checks, "CORS Configuration")),
                        "CORS should require reflection, not just sensitive data")

    def test_origin_reflection_trips_cors_high(self):
        checks = self.scan("vuln-cors")
        cors = _by_name(checks, "CORS Configuration")
        self.assertTrue(cors, "expected CORS checks to run")
        for check in cors:
            self.assertFalse(check.passed, "reflected Origin + secrets must be flagged")
            self.assertEqual(check.risk_level, RiskLevel.HIGH,
                             "Allow-Credentials:true makes it HIGH severity")

        # Auth checks have no Origin header -> server returns 401 -> clean.
        for name in (
            "SSE Endpoint Authentication",
            "Message Endpoint Authentication",
            "MCP Endpoint Authentication",
            "Authorization Header Validation",
        ):
            self.assertTrue(_one(checks, name).passed,
                            f"{name} should pass against the CORS-only fixture")

    def test_secure_control_has_no_findings(self):
        checks = self.scan("secure")
        failed = [c for c in checks if not c.passed]
        self.assertEqual(failed, [], f"secure control produced findings: {failed}")
        self.assertFalse(
            any(c.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH) for c in checks),
            "negative control must not raise CRITICAL/HIGH",
        )

    def test_mcp_handshake_confirms_real_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _MCPRealHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            checks = MCPScanner(f"http://{host}:{port}", timeout=5).scan()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        handshake = _one(checks, "MCP Protocol Handshake")
        self.assertTrue(handshake.passed)
        self.assertIn("Confirmed MCP server: fixture-mcp 9.9", handshake.details)

    def test_mcp_handshake_not_confirmed_on_non_mcp(self):
        # The locked/secure fixture answers 401, so the handshake cannot confirm.
        checks = self.scan("secure")
        handshake = _one(checks, "MCP Protocol Handshake")
        self.assertTrue(handshake.passed)  # informational, never a finding
        self.assertIn("not confirmed", handshake.details)

    def test_html_catch_all_is_not_a_finding(self):
        # Regression: an SPA/docs server that returns 200 text/html for every
        # path must NOT be flagged as a zero-auth MCP endpoint (previously the
        # status-only heuristic raised a false CRITICAL on /sse here).
        checks = self.scan("spa-html")
        failed = [c for c in checks if not c.passed]
        self.assertEqual(failed, [], f"HTML catch-all produced false findings: {failed}")
        sse = _one(checks, "SSE Endpoint Authentication")
        self.assertTrue(sse.passed, "200 text/html on /sse must not be a finding")


if __name__ == "__main__":
    unittest.main()
