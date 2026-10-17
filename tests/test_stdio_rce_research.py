#!/usr/bin/env python3
"""Tests for the local MCP STDIO-RCE research harness (research/mcp_stdio_rce/).

All loopback-only. One test performs a *benign* demonstration that the
vulnerable mock executes a command at registration time (it creates a marker
file in a temp dir), proving the "execution at spawn time" property without any
real payload. The detector tests confirm it flags the vulnerable mock and stays
clean on the hardened one -- without registering or executing anything.
"""
import importlib.util
import os
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

_SERVED = ("/mcp", "/sse", "/mcp/servers", "/")


class _DnsVulnerable(BaseHTTPRequestHandler):
    """Ignores Host/Origin entirely: serves every known path regardless."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path.split("?", 1)[0] in _SERVED:
            body = b'{"ok":true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")  # also reflects any origin
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_HEAD = do_GET


class _DnsHardened(BaseHTTPRequestHandler):
    """Pins Host/Origin to loopback; foreign Host -> 421, foreign Origin -> 403."""

    def log_message(self, *args):
        pass

    def do_GET(self):
        hostname = self.headers.get("Host", "").split(":", 1)[0]
        if hostname not in ("127.0.0.1", "localhost"):
            return self._status(421, "Misdirected Request")
        origin = self.headers.get("Origin")
        if origin and origin not in ("http://localhost", "http://127.0.0.1"):
            return self._status(403, "Forbidden")
        if self.path.split("?", 1)[0] in _SERVED:
            return self._status(200, "OK", b'{"ok":true}')
        return self._status(404, "Not Found")

    def _status(self, code, reason, body=b""):
        self.send_response(code, reason)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    do_HEAD = do_GET

_HERE = os.path.dirname(os.path.abspath(__file__))
_RESEARCH = os.path.join(os.path.dirname(_HERE), "research", "mcp_stdio_rce")


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f"stdio_rce_{name}", os.path.join(_RESEARCH, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


vulnerable_router = _load("vulnerable_router")
hardened_router = _load("hardened_router")
detector = _load("detector")


class _Server:
    def __init__(self, handler_cls):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
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


class StdioRceResearchTests(unittest.TestCase):
    def setUp(self):
        # Reset the shared class-level registries between tests.
        vulnerable_router.VulnerableRouter.registry = {}
        hardened_router.HardenedRouter.registry = {}

    def test_detector_flags_vulnerable_router(self):
        with _Server(vulnerable_router.VulnerableRouter) as srv:
            finding = detector.detect_unauth_mcp_config(srv.url, timeout=5)
        self.assertIsNotNone(finding, "detector should flag the unauth config endpoint")
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertTrue(finding["evidence"], "finding must cite evidence")
        # The vulnerable registry must stay empty: the detector must not register.
        self.assertEqual(vulnerable_router.VulnerableRouter.registry, {})

    def test_detector_clean_on_hardened_router(self):
        with _Server(hardened_router.HardenedRouter) as srv:
            finding = detector.detect_unauth_mcp_config(srv.url, timeout=5)
        self.assertIsNone(finding, "hardened router (401) must not be flagged")

    def test_hardened_router_enforces_auth_and_allowlist(self):
        with _Server(hardened_router.HardenedRouter) as srv:
            # Unauthenticated registration is rejected outright.
            r = requests.post(f"{srv.url}/mcp/servers",
                              json={"name": "x", "command": ["python3"]}, timeout=5)
            self.assertEqual(r.status_code, 401)
            # Authenticated but disallowed launcher -> 403.
            auth = {"Authorization": "Bearer change-me"}
            r = requests.post(f"{srv.url}/mcp/servers", headers=auth,
                              json={"name": "x", "command": ["/bin/sh", "-c", "id"]}, timeout=5)
            self.assertEqual(r.status_code, 403)
            # Authenticated + allowlisted launcher, no metacharacters -> accepted.
            r = requests.post(f"{srv.url}/mcp/servers", headers=auth,
                              json={"name": "ok", "command": ["npx", "server-filesystem"]}, timeout=5)
            self.assertEqual(r.status_code, 200)
            self.assertFalse(r.json()["spawned"], "hardened mock must not execute input")

    def test_detector_flags_missing_host_origin_validation(self):
        with _Server(_DnsVulnerable) as srv:
            finding = detector.detect_dns_rebinding_precondition(srv.url, timeout=5)
        self.assertIsNotNone(finding, "should flag a server that ignores Host/Origin")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertTrue(finding["evidence"])
        self.assertTrue(any("Origin reflected" in e for e in finding["evidence"]),
                        "wildcard ACAO should be noted as Origin reflection")

    def test_detector_clean_on_host_origin_pinned_server(self):
        with _Server(_DnsHardened) as srv:
            finding = detector.detect_dns_rebinding_precondition(srv.url, timeout=5)
        self.assertIsNone(finding, "a Host/Origin-pinned server must not be flagged")

    def test_vulnerable_router_executes_at_registration(self):
        # Benign demonstration of "execution at spawn time": register a command
        # that just creates a marker file, then assert the file appears.
        with tempfile.TemporaryDirectory() as tmp:
            marker = os.path.join(tmp, "spawned_marker")
            with _Server(vulnerable_router.VulnerableRouter) as srv:
                resp = requests.post(
                    f"{srv.url}/mcp/servers",
                    json={"name": "demo",
                          "command": ["python3", "-c", f"open({marker!r}, 'w').close()"]},
                    timeout=5,
                )
                self.assertEqual(resp.status_code, 200)
                self.assertTrue(resp.json()["spawned"])
                # Spawn is async; poll briefly for the marker.
                for _ in range(50):
                    if os.path.exists(marker):
                        break
                    time.sleep(0.1)
            self.assertTrue(os.path.exists(marker),
                            "command should have executed at registration time")


if __name__ == "__main__":
    unittest.main()
