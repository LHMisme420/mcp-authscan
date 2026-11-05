"""tests for tools/scope_check.py — standalone scope-enforcement checker."""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "scope_check.py"
sys.path.insert(0, str(ROOT / "tools"))

import scope_check as sc  # noqa: E402


def _run_tool(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
    )


def test_fixture_strict_pass():
    r = sc.run_fixture_mode("strict")
    assert r["verdict"] == "PASS"
    assert r["exit_code"] == 0
    assert sc.WWW_AUTH_INSUFFICIENT in (r["mcp_call"]["response"]["www_authenticate"] or "")
    assert r["fixture_mcp_calls"], "MCP must be called"
    assert all(c["method"] == "tools/call" for c in r["fixture_mcp_calls"])
    assert all(c["tool"] == sc.FIXTURE_TOOL for c in r["fixture_mcp_calls"])


def test_fixture_lax_fail():
    r = sc.run_fixture_mode("lax")
    assert r["verdict"] == "FAIL"
    assert r["exit_code"] == 1
    assert r["exit_code"] != 0
    assert all(c["method"] == "tools/call" for c in r["fixture_mcp_calls"])
    assert all(c["tool"] == sc.FIXTURE_TOOL for c in r["fixture_mcp_calls"])


def test_fixture_as_widens_excluded():
    r = sc.run_fixture_mode("as-widens")
    assert r["verdict"] == "EXCLUDED"
    assert r["exit_code"] == 3
    assert r["reason"] == "AS will not issue a narrower grant"
    assert sc.FIXTURE_REQUIRED_SCOPE in (r.get("returned_scope") or "")
    # Must not call MCP once narrowing failed.
    assert r["fixture_mcp_calls"] == []


def test_strict_and_lax_token_requests_match():
    """Requests in strict and lax differ only in server behavior."""
    a = sc.run_fixture_mode("strict")
    b = sc.run_fixture_mode("lax")
    assert a["fixture_token_requests"]
    assert b["fixture_token_requests"]
    # Compare the form fields the client sent (ignore server-side token values).
    ra, rb = a["fixture_token_requests"][0], b["fixture_token_requests"][0]
    for key in ("grant_type", "client_id", "client_secret", "scope"):
        assert ra.get(key) == rb.get(key), key
    assert ra["scope"] == sc.FIXTURE_NARROW_SCOPE
    assert sc.FIXTURE_REQUIRED_SCOPE not in ra["scope"].split()


def test_cli_fixture_exit_codes():
    for mode, expected in (("strict", 0), ("lax", 1), ("as-widens", 3)):
        proc = _run_tool(["--fixture", mode])
        assert proc.returncode == expected, (mode, proc.stdout, proc.stderr)


def test_missing_args_exit_2():
    proc = _run_tool([])
    assert proc.returncode == 2
    proc2 = _run_tool(["--mcp-url", "http://127.0.0.1:9/mcp"])
    assert proc2.returncode == 2


def test_opaque_token_excluded_cannot_establish_issued_scope():
    """Opaque access_token with no scope field → EXCLUDED, not a JWT fall-through."""

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
            if self.path == "/token":
                body = json.dumps(
                    {"access_token": "opaque-unscoped-token", "token_type": "Bearer"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        result = sc.run_scope_check(
            mcp_url=base + "/mcp",
            tool="read_status",
            required_scope="tools:invoke",
            requested_scope="openid",
            client_id="c",
            client_secret="s",
            token_endpoint=base + "/token",
            skip_discovery=True,
        )
    finally:
        srv.shutdown()
        srv.server_close()

    assert result["verdict"] == "EXCLUDED"
    assert result["reason"] == "cannot establish issued scope"
    assert result["exit_code"] == 3
    assert result["mcp_call"] is None


def test_jwt_scope_claim_is_second_proof_path():
    """When token response has no scope field, a readable JWT scope claim proves issuance."""

    def b64(data: dict) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    header = b64({"alg": "none", "typ": "JWT"})
    payload = b64({"scope": "openid profile"})
    token = "%s.%s." % (header, payload)

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n)
            if self.path == "/token":
                out = json.dumps(
                    {"access_token": token, "token_type": "Bearer"}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)
                return
            if self.path.startswith("/mcp"):
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    'Bearer error="insufficient_scope"',
                )
                self.send_header("Content-Type", "application/json")
                msg = b'{"jsonrpc":"2.0","id":1,"error":{"code":-32001}}'
                self.send_header("Content-Length", str(len(msg)))
                self.end_headers()
                self.wfile.write(msg)
                return
            self.send_response(404)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        result = sc.run_scope_check(
            mcp_url=base + "/mcp",
            tool="read_status",
            required_scope="tools:invoke",
            requested_scope="openid profile",
            client_id="c",
            client_secret="s",
            token_endpoint=base + "/token",
            skip_discovery=True,
        )
    finally:
        srv.shutdown()
        srv.server_close()

    assert result["proof_source"] == "jwt_payload"
    assert result["verdict"] == "PASS"
    assert result["exit_code"] == 0


def test_www_authenticate_requires_exact_substring():
    scopes, proof, excl = sc.establish_issued_scopes(
        {"scope": "openid", "access_token": "x"}, "x"
    )
    assert excl is None
    assert "openid" in scopes

    # Refusal without the exact error string is FAIL, not PASS.
    verdict, _reason = sc.evaluate_mcp_response(
        {
            "response": {
                "status": 401,
                "www_authenticate": 'Bearer error="invalid_token"',
                "body_json": {},
                "body_text": "",
            }
        }
    )
    assert verdict == "FAIL"


def test_only_named_tool_in_call_payload():
    """call_named_tool builds tools/call for the given name only — no write/delete/execute."""
    seen = {}

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n)
            seen["body"] = json.loads(raw.decode())
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Bearer error="insufficient_scope"')
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        sc.call_named_tool(base + "/mcp", "tok", "read_status")
    finally:
        srv.shutdown()
        srv.server_close()

    body = seen["body"]
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "read_status"
    assert set(body["params"].keys()) <= {"name", "arguments"}
    forbidden = {"write", "delete", "execute", "shell", "rm"}
    assert body["params"]["name"] not in forbidden
