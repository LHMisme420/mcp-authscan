#!/usr/bin/env python3
"""Standalone MCP scope-enforcement check (outside the default scan path).

Property under test: a token is accepted by the MCP server, but the named tool
is refused when that token lacks the required scope.

Token path:
  1. Read protected-resource metadata for scopes_supported and the AS.
  2. Register a client via DCR when advertised and no client credentials were
     supplied; otherwise use --client-id / --client-secret.
  3. POST to the token endpoint with grant_type, client_id, client_secret, and a
     deliberately narrowed scope (required scope withheld).
  4. Prove issued scopes from the token response ``scope`` field first, then a
     JWT payload decode. Nothing else. The access token presented to MCP must
     come from that exchange.

Exit codes for this tool only:
  PASS 0 | FAIL 1 | usage 2 | EXCLUDED 3 | NOT_OBSERVED 4
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

import requests

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_EXCLUDED = 3
EXIT_NOT_OBSERVED = 4

WWW_AUTH_INSUFFICIENT = 'error="insufficient_scope"'

# Fixture defaults (dummy values; never live credentials).
FIXTURE_TOOL = "read_status"
FIXTURE_REQUIRED_SCOPE = "tools:invoke"
FIXTURE_NARROW_SCOPE = "openid profile"
FIXTURE_CLIENT_ID = "fixture-client"
FIXTURE_CLIENT_SECRET = "fixture-secret"
FIXTURE_GRANT = "client_credentials"


# ---------------------------------------------------------------------------
# Scope proof: response scope field first, JWT payload second, nothing else.
# ---------------------------------------------------------------------------
def _b64url_json(segment: str) -> dict[str, Any] | None:
    pad = "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(segment + pad)
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _scopes_from_claim(value: Any) -> set[str] | None:
    if isinstance(value, str):
        parts = [p for p in value.split() if p]
        return set(parts) if parts else set()
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return set(value)
    return None


def jwt_payload_scopes(access_token: str) -> set[str] | None:
    """Return scopes from a well-formed JWT payload, or None if not a readable JWT."""
    if not isinstance(access_token, str) or access_token.count(".") != 2:
        return None
    _hdr, payload_seg, _sig = access_token.split(".")
    payload = _b64url_json(payload_seg)
    if payload is None:
        return None
    for key in ("scope", "scp"):
        if key in payload:
            scopes = _scopes_from_claim(payload[key])
            if scopes is not None:
                return scopes
    return None


def establish_issued_scopes(
    token_body: dict[str, Any], access_token: str
) -> tuple[set[str] | None, str | None, str | None]:
    """Prove issued scopes.

    Returns (scopes, proof_source, exclude_reason).
    exclude_reason is set when scopes cannot be established.
    """
    if "scope" in token_body:
        scopes = _scopes_from_claim(token_body.get("scope"))
        if scopes is not None:
            return scopes, "token_response.scope", None
    jwt_scopes = jwt_payload_scopes(access_token)
    if jwt_scopes is not None:
        return jwt_scopes, "jwt_payload", None
    return None, None, "cannot establish issued scope"


# ---------------------------------------------------------------------------
# Token exchange (real HTTP). Record full request/response for output.
# ---------------------------------------------------------------------------
def obtain_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    scope: str,
    grant_type: str = FIXTURE_GRANT,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """POST a real token request. Returns an exchange record.

    The access_token field is the value to present to MCP (may be None on failure).
    Printed/serialized forms redact client_secret and may shorten live-looking tokens;
    fixture dummy values remain visible.
    """
    form = {
        "grant_type": grant_type,
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }
    record: dict[str, Any] = {
        "request": {
            "method": "POST",
            "url": token_endpoint,
            "headers": {"Content-Type": headers["Content-Type"], "Accept": headers["Accept"]},
            "body": {
                "grant_type": grant_type,
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            },
        },
        "response": None,
        "access_token": None,
        "error": None,
    }
    try:
        resp = requests.post(token_endpoint, data=form, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        record["error"] = "token_request_failed: %s" % exc
        return record

    resp_headers = {k: v for k, v in resp.headers.items()}
    body_text = resp.text
    body_json: dict[str, Any] | None
    try:
        parsed = resp.json()
        body_json = parsed if isinstance(parsed, dict) else None
    except ValueError:
        body_json = None

    record["response"] = {
        "status": resp.status_code,
        "headers": resp_headers,
        "body_text": body_text,
        "body_json": body_json,
    }
    if body_json and isinstance(body_json.get("access_token"), str):
        record["access_token"] = body_json["access_token"]
    return record


def redact_exchange_for_display(record: dict[str, Any]) -> dict[str, Any]:
    """Copy of the exchange safe to print with sensitive fields always redacted."""
    out = json.loads(json.dumps(record))
    body = out.get("request", {}).get("body")
    if isinstance(body, dict) and "client_secret" in body:
        body["client_secret"] = "<redacted>"
    token = out.get("access_token")
    resp = out.get("response") or {}
    bj = resp.get("body_json") if isinstance(resp, dict) else None
    if isinstance(bj, dict) and isinstance(bj.get("access_token"), str):
        raw = bj["access_token"]
        # Fixture tokens stay visible; anything else is shortened.
        if not (
            raw.startswith("fixture-")
            or raw.startswith("eyJ")  # JWT shown truncated below
            or raw in ("opaque-unscoped-token",)
        ):
            bj["access_token"] = raw[:8] + "…<redacted>"
        elif raw.startswith("eyJ") and len(raw) > 40:
            bj["access_token"] = raw  # fixture JWTs are short/local; keep for proof
    if isinstance(token, str) and token.startswith("eyJ") is False:
        if not token.startswith("fixture-") and token != "opaque-unscoped-token":
            out["access_token"] = token[:8] + "…<redacted>"
    return out


# ---------------------------------------------------------------------------
# Discovery + optional DCR
# ---------------------------------------------------------------------------
def _parse_resource_metadata_url(www_auth: str | None) -> str | None:
    if not www_auth:
        return None
    marker = "resource_metadata="
    lower = www_auth.lower()
    idx = lower.find(marker)
    if idx < 0:
        return None
    rest = www_auth[idx + len(marker) :].strip()
    if rest.startswith('"'):
        end = rest.find('"', 1)
        if end > 1:
            return rest[1:end]
    return rest.split()[0].strip().rstrip(",") if rest else None


def fetch_json(url: str, timeout: float = 10.0) -> tuple[int, dict[str, Any] | None, str]:
    try:
        r = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    except requests.RequestException as exc:
        return 0, None, str(exc)
    try:
        data = r.json()
    except ValueError:
        return r.status_code, None, r.text
    if not isinstance(data, dict):
        return r.status_code, None, r.text
    return r.status_code, data, r.text


def discover(mcp_url: str, timeout: float = 10.0) -> dict[str, Any]:
    """Resolve AS, token endpoint, scopes_supported, optional registration_endpoint."""
    out: dict[str, Any] = {
        "mcp_url": mcp_url,
        "resource_metadata_url": None,
        "resource_metadata": None,
        "as_metadata_url": None,
        "as_metadata": None,
        "scopes_supported": None,
        "token_endpoint": None,
        "registration_endpoint": None,
        "error": None,
    }
    try:
        probe = requests.get(mcp_url, timeout=timeout, allow_redirects=False)
    except requests.RequestException as exc:
        out["error"] = "mcp_probe_failed: %s" % exc
        return out

    www = probe.headers.get("WWW-Authenticate") or probe.headers.get("www-authenticate")
    rm_url = _parse_resource_metadata_url(www)
    if not rm_url:
        # try well-known relative to origin
        parts = urlsplit(mcp_url)
        origin = "%s://%s" % (parts.scheme, parts.netloc)
        rm_url = urljoin(origin + "/", ".well-known/oauth-protected-resource")
    out["resource_metadata_url"] = rm_url
    code, rm, _ = fetch_json(rm_url, timeout=timeout)
    if not rm:
        out["error"] = "resource_metadata_unavailable status=%s" % code
        return out
    out["resource_metadata"] = rm
    scopes = rm.get("scopes_supported")
    if isinstance(scopes, list):
        out["scopes_supported"] = [s for s in scopes if isinstance(s, str)]
    servers = rm.get("authorization_servers")
    if not isinstance(servers, list) or not servers or not isinstance(servers[0], str):
        out["error"] = "resource_metadata missing authorization_servers"
        return out
    as_id = servers[0].rstrip("/") + "/"
    as_meta_url = urljoin(as_id, ".well-known/oauth-authorization-server")
    out["as_metadata_url"] = as_meta_url
    code, as_meta, _ = fetch_json(as_meta_url, timeout=timeout)
    if not as_meta:
        out["error"] = "as_metadata_unavailable status=%s" % code
        return out
    out["as_metadata"] = as_meta
    te = as_meta.get("token_endpoint")
    if not isinstance(te, str) or not te:
        out["error"] = "as_metadata missing token_endpoint"
        return out
    out["token_endpoint"] = te
    reg = as_meta.get("registration_endpoint")
    if isinstance(reg, str) and reg:
        out["registration_endpoint"] = reg
    return out


def register_client(registration_endpoint: str, timeout: float = 10.0) -> dict[str, Any]:
    payload = {
        "client_name": "mcp-authscan-scope-check",
        "token_endpoint_auth_method": "client_secret_post",
        "grant_types": ["client_credentials"],
    }
    record: dict[str, Any] = {"request": payload, "response": None, "error": None}
    try:
        r = requests.post(
            registration_endpoint,
            json=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        record["error"] = str(exc)
        return record
    try:
        body = r.json()
    except ValueError:
        body = None
    record["response"] = {"status": r.status_code, "body": body, "text": r.text}
    return record


# ---------------------------------------------------------------------------
# MCP tools/call — only the named tool.
# ---------------------------------------------------------------------------
def call_named_tool(
    mcp_url: str, access_token: str, tool_name: str, timeout: float = 10.0
) -> dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": {}},
    }
    headers = {
        "Authorization": "Bearer %s" % access_token,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    record: dict[str, Any] = {
        "request": {
            "method": "POST",
            "url": mcp_url,
            "jsonrpc_method": "tools/call",
            "tool": tool_name,
            # Authorization value not echoed; presence only.
            "authorization": "Bearer <token-from-exchange>",
        },
        "response": None,
        "error": None,
    }
    try:
        r = requests.post(mcp_url, json=payload, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        record["error"] = "mcp_call_failed: %s" % exc
        return record
    www = r.headers.get("WWW-Authenticate") or r.headers.get("www-authenticate") or ""
    try:
        body_json = r.json()
    except ValueError:
        body_json = None
    record["response"] = {
        "status": r.status_code,
        "www_authenticate": www,
        "body_json": body_json,
        "body_text": r.text,
    }
    return record


def evaluate_mcp_response(mcp_record: dict[str, Any]) -> tuple[str, str]:
    """Return (verdict, reason) for the MCP tools/call response.

    PASS requires HTTP 403 and WWW-Authenticate carrying error="insufficient_scope".
    A 401 with that challenge is NOT_OBSERVED; the reason names the 401 status.
    """
    if mcp_record.get("error"):
        return "NOT_OBSERVED", mcp_record["error"]
    resp = mcp_record.get("response") or {}
    status = resp.get("status")
    www = resp.get("www_authenticate") or ""
    body = resp.get("body_json")

    if WWW_AUTH_INSUFFICIENT in www:
        if status == 403:
            return "PASS", (
                "HTTP 403 with WWW-Authenticate containing %s" % WWW_AUTH_INSUFFICIENT
            )
        if status == 401:
            return "NOT_OBSERVED", (
                "HTTP 401 with %s is not a conclusive scope refusal; "
                "PASS requires HTTP 403" % WWW_AUTH_INSUFFICIENT
            )
        return "NOT_OBSERVED", (
            "WWW-Authenticate contains %s but HTTP status was %s, not 403"
            % (WWW_AUTH_INSUFFICIENT, status)
        )

    # Accepted tool result → FAIL (scope not enforced).
    if status == 200 and isinstance(body, dict) and "result" in body:
        return "FAIL", "tools/call accepted with result; scope not enforced"
    if status == 200 and isinstance(body, dict) and "error" not in body:
        return "FAIL", "tools/call HTTP 200 without insufficient_scope"

    # Refusal without the exact WWW-Authenticate error → FAIL (wrong refusal signal).
    if status in (401, 403):
        return "FAIL", "refused without exact %s (HTTP %s, WWW-Authenticate=%r)" % (
            WWW_AUTH_INSUFFICIENT,
            status,
            www,
        )

    return "NOT_OBSERVED", "MCP response did not demonstrate enforcement or acceptance (status=%s)" % status


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_scope_check(
    *,
    mcp_url: str,
    tool: str,
    required_scope: str,
    requested_scope: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    token_endpoint: str | None = None,
    grant_type: str = FIXTURE_GRANT,
    timeout: float = 10.0,
    skip_discovery: bool = False,
) -> dict[str, Any]:
    """Run the check. Returns a result dict with verdict, reason, exit_code, exchange, etc."""
    result: dict[str, Any] = {
        "verdict": None,
        "reason": None,
        "exit_code": EXIT_NOT_OBSERVED,
        "discovery": None,
        "registration": None,
        "token_exchange": None,
        "issued_scopes": None,
        "proof_source": None,
        "mcp_call": None,
        "tool": tool,
        "required_scope": required_scope,
        "requested_scope": requested_scope,
    }

    if required_scope in requested_scope.split():
        result["verdict"] = "EXCLUDED"
        result["reason"] = (
            "requested scope must withhold the required scope under test; "
            "got required=%r requested=%r" % (required_scope, requested_scope)
        )
        result["exit_code"] = EXIT_EXCLUDED
        return result

    te = token_endpoint
    cid = client_id
    csec = client_secret

    if not skip_discovery or te is None:
        disc = discover(mcp_url, timeout=timeout)
        result["discovery"] = disc
        if disc.get("error") and te is None:
            result["verdict"] = "NOT_OBSERVED"
            result["reason"] = disc["error"]
            result["exit_code"] = EXIT_NOT_OBSERVED
            return result
        if te is None:
            te = disc.get("token_endpoint")
        if cid is None and disc.get("registration_endpoint"):
            reg = register_client(disc["registration_endpoint"], timeout=timeout)
            result["registration"] = reg
            body = (reg.get("response") or {}).get("body") or {}
            if not isinstance(body.get("client_id"), str):
                result["verdict"] = "NOT_OBSERVED"
                result["reason"] = "dynamic registration did not return client_id"
                result["exit_code"] = EXIT_NOT_OBSERVED
                return result
            cid = body["client_id"]
            csec = body.get("client_secret") or ""

    if te is None and not skip_discovery:
        result["verdict"] = "EXCLUDED"
        result["reason"] = (
            "no authorization server published at this endpoint; discovery named no "
            "token_endpoint, so scope enforcement cannot be exercised"
        )
        result["exit_code"] = EXIT_EXCLUDED
        return result

    if not te or not cid or csec is None:
        result["verdict"] = "NOT_OBSERVED"
        result["reason"] = "missing token_endpoint or client credentials after discovery"
        result["exit_code"] = EXIT_NOT_OBSERVED
        return result

    exchange = obtain_token(te, cid, csec, requested_scope, grant_type=grant_type, timeout=timeout)
    result["token_exchange"] = redact_exchange_for_display(exchange)

    if exchange.get("error"):
        result["verdict"] = "NOT_OBSERVED"
        result["reason"] = exchange["error"]
        result["exit_code"] = EXIT_NOT_OBSERVED
        return result

    resp = exchange.get("response") or {}
    body_json = resp.get("body_json") if isinstance(resp, dict) else None
    access_token = exchange.get("access_token")
    if not isinstance(body_json, dict) or not isinstance(access_token, str) or not access_token:
        result["verdict"] = "NOT_OBSERVED"
        result["reason"] = "token endpoint did not return an access_token (status=%s)" % resp.get(
            "status"
        )
        result["exit_code"] = EXIT_NOT_OBSERVED
        return result

    scopes, proof, excl = establish_issued_scopes(body_json, access_token)
    result["proof_source"] = proof
    if excl:
        result["verdict"] = "EXCLUDED"
        result["reason"] = excl  # 'cannot establish issued scope'
        result["exit_code"] = EXIT_EXCLUDED
        return result

    assert scopes is not None
    result["issued_scopes"] = sorted(scopes)

    if required_scope in scopes:
        returned = body_json.get("scope")
        if not isinstance(returned, str):
            returned = " ".join(sorted(scopes))
        result["verdict"] = "EXCLUDED"
        result["reason"] = "AS will not issue a narrower grant"
        result["returned_scope"] = returned
        result["exit_code"] = EXIT_EXCLUDED
        return result

    mcp_record = call_named_tool(mcp_url, access_token, tool, timeout=timeout)
    result["mcp_call"] = mcp_record
    verdict, reason = evaluate_mcp_response(mcp_record)
    result["verdict"] = verdict
    result["reason"] = reason
    result["exit_code"] = {
        "PASS": EXIT_PASS,
        "FAIL": EXIT_FAIL,
        "EXCLUDED": EXIT_EXCLUDED,
        "NOT_OBSERVED": EXIT_NOT_OBSERVED,
    }[verdict]
    return result


def mcp_http_status(result: dict[str, Any]) -> int | None:
    mcp = result.get("mcp_call") or {}
    resp = mcp.get("response") if isinstance(mcp, dict) else None
    if isinstance(resp, dict) and isinstance(resp.get("status"), int):
        return resp["status"]
    return None


def result_as_jsonable(result: dict[str, Any]) -> dict[str, Any]:
    """Machine-readable view for --json. Token exchange is already redacted."""
    return {
        "verdict": result.get("verdict"),
        "reason": result.get("reason"),
        "exit_code": result.get("exit_code"),
        "tool": result.get("tool"),
        "required_scope": result.get("required_scope"),
        "requested_scope": result.get("requested_scope"),
        "issued_scopes": result.get("issued_scopes"),
        "returned_scope": result.get("returned_scope"),
        "proof_source": result.get("proof_source"),
        "mcp_http_status": mcp_http_status(result),
        "token_exchange": result.get("token_exchange"),
        "mcp_call": result.get("mcp_call"),
        "fixture_mode": result.get("fixture_mode"),
    }


def print_result(result: dict[str, Any], as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(result_as_jsonable(result), indent=2, sort_keys=True))
        return
    print("verdict: %s" % result["verdict"])
    print("reason: %s" % result["reason"])
    if result.get("returned_scope") is not None:
        print("returned_scope: %s" % result["returned_scope"])
    if result.get("issued_scopes") is not None:
        print("issued_scopes: %s" % " ".join(result["issued_scopes"]))
    if result.get("proof_source"):
        print("proof_source: %s" % result["proof_source"])
    print("tool: %s" % result.get("tool"))
    print("required_scope: %s" % result.get("required_scope"))
    print("requested_scope: %s" % result.get("requested_scope"))
    status = mcp_http_status(result)
    if status is not None:
        print("mcp_http_status: %s" % status)
    print("--- token exchange ---")
    token_exchange = result.get("token_exchange")
    if isinstance(token_exchange, dict):
        token_exchange = redact_exchange_for_display(token_exchange)
    print(json.dumps(token_exchange, indent=2, sort_keys=True))
    print("--- mcp call ---")
    print(json.dumps(result.get("mcp_call"), indent=2, sort_keys=True))
    print("exit_code: %s" % result["exit_code"])


# ---------------------------------------------------------------------------
# Local fixture: strict / lax / as-widens
# ---------------------------------------------------------------------------
class _FixtureState:
    def __init__(self, mode: str):
        self.mode = mode
        self.tokens: dict[str, str] = {}
        self.mcp_calls: list[dict[str, Any]] = []
        self.token_requests: list[dict[str, Any]] = []


def _make_handler(state: _FixtureState):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _read_body(self) -> bytes:
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def _send(self, code: int, body: bytes, headers: dict[str, str] | None = None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _json(self, code: int, obj: Any, extra_headers: dict[str, str] | None = None):
            raw = json.dumps(obj).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if extra_headers:
                headers.update(extra_headers)
            self._send(code, raw, headers)

        def do_GET(self):
            base = "http://127.0.0.1:%d" % self.server.server_address[1]
            if self.path.startswith("/mcp"):
                self.send_response(401)
                self.send_header(
                    "WWW-Authenticate",
                    'Bearer resource_metadata="%s/.well-known/oauth-protected-resource"' % base,
                )
                self.end_headers()
                return
            if self.path.endswith("/.well-known/oauth-protected-resource"):
                self._json(
                    200,
                    {
                        "resource": base + "/mcp",
                        "authorization_servers": [base],
                        "scopes_supported": [
                            "openid",
                            "profile",
                            FIXTURE_REQUIRED_SCOPE,
                        ],
                    },
                )
                return
            if self.path.endswith("/.well-known/oauth-authorization-server"):
                self._json(
                    200,
                    {
                        "issuer": base,
                        "token_endpoint": base + "/token",
                        "registration_endpoint": base + "/register",
                        "grant_types_supported": ["client_credentials"],
                        "token_endpoint_auth_methods_supported": ["client_secret_post"],
                    },
                )
                return
            self._send(404, b"not found")

        def do_POST(self):
            base = "http://127.0.0.1:%d" % self.server.server_address[1]
            raw = self._read_body()
            if self.path == "/register":
                cid = "dcr-" + uuid.uuid4().hex[:8]
                csec = "dcr-secret-" + uuid.uuid4().hex[:8]
                self._json(
                    201,
                    {
                        "client_id": cid,
                        "client_secret": csec,
                        "grant_types": ["client_credentials"],
                        "token_endpoint_auth_method": "client_secret_post",
                    },
                )
                return

            if self.path == "/token":
                params = {k: v[0] for k, v in parse_qs(raw.decode("utf-8")).items()}
                state.token_requests.append(dict(params))
                if params.get("client_id") in (None, ""):
                    self._json(400, {"error": "invalid_client"})
                    return
                # AS-widens: ignore narrowing and return the required scope too.
                if state.mode == "as-widens":
                    granted = "%s %s" % (FIXTURE_NARROW_SCOPE, FIXTURE_REQUIRED_SCOPE)
                else:
                    # Honour requested scope (narrowing).
                    granted = params.get("scope") or FIXTURE_NARROW_SCOPE
                token = "fixture-%s-%s" % (state.mode, uuid.uuid4().hex[:12])
                state.tokens[token] = granted
                self._json(
                    200,
                    {
                        "access_token": token,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": granted,
                    },
                )
                return

            if self.path.startswith("/mcp"):
                try:
                    req = json.loads(raw.decode("utf-8") or "{}")
                except json.JSONDecodeError:
                    req = {}
                method = req.get("method")
                params = req.get("params") if isinstance(req.get("params"), dict) else {}
                tool_name = params.get("name")
                auth = self.headers.get("Authorization") or ""
                state.mcp_calls.append(
                    {
                        "method": method,
                        "tool": tool_name,
                        "path": self.path,
                    }
                )
                if method != "tools/call":
                    self._json(200, {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32601, "message": "only tools/call supported in fixture"}})
                    return

                token = ""
                if auth.lower().startswith("bearer "):
                    token = auth.split(" ", 1)[1].strip()

                if state.mode == "strict":
                    self.send_response(403)
                    self.send_header(
                        "WWW-Authenticate",
                        'Bearer %s, scope="%s"' % (WWW_AUTH_INSUFFICIENT, FIXTURE_REQUIRED_SCOPE),
                    )
                    self.send_header("Content-Type", "application/json")
                    body = json.dumps(
                        {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32001, "message": "insufficient_scope"}}
                    ).encode()
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return

                if state.mode == "lax":
                    # Accept the call — same client request as strict; only server differs.
                    self._json(
                        200,
                        {
                            "jsonrpc": "2.0",
                            "id": req.get("id"),
                            "result": {
                                "content": [{"type": "text", "text": "ok"}],
                                "isError": False,
                            },
                        },
                    )
                    return

                # as-widens should never reach MCP (excluded at token proof); if it does:
                self._json(
                    200,
                    {
                        "jsonrpc": "2.0",
                        "id": req.get("id"),
                        "result": {"content": [{"type": "text", "text": "should-not-run"}]},
                    },
                )
                return

            self._send(404, b"not found")

    return Handler


def start_fixture(mode: str) -> tuple[ThreadingHTTPServer, _FixtureState, str]:
    if mode not in ("strict", "lax", "as-widens"):
        raise ValueError("unknown fixture mode: %s" % mode)
    state = _FixtureState(mode)
    handler = _make_handler(state)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    base = "http://127.0.0.1:%d" % srv.server_address[1]
    return srv, state, base


def run_fixture_mode(mode: str) -> dict[str, Any]:
    srv, state, base = start_fixture(mode)
    try:
        result = run_scope_check(
            mcp_url=base + "/mcp",
            tool=FIXTURE_TOOL,
            required_scope=FIXTURE_REQUIRED_SCOPE,
            requested_scope=FIXTURE_NARROW_SCOPE,
            client_id=FIXTURE_CLIENT_ID,
            client_secret=FIXTURE_CLIENT_SECRET,
            token_endpoint=base + "/token",
            grant_type=FIXTURE_GRANT,
            skip_discovery=True,
        )
        result["fixture_mode"] = mode
        result["fixture_mcp_calls"] = list(state.mcp_calls)
        result["fixture_token_requests"] = list(state.token_requests)
        return result
    finally:
        srv.shutdown()
        srv.server_close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check that an MCP server enforces scopes on a named tool."
    )
    p.add_argument(
        "--fixture",
        choices=("strict", "lax", "as-widens"),
        help="run against a local three-mode fixture and exit",
    )
    p.add_argument("--mcp-url", help="MCP endpoint URL")
    p.add_argument("--token-endpoint", help="AS token endpoint (skips discovery when set with client creds)")
    p.add_argument("--client-id")
    p.add_argument("--client-secret")
    p.add_argument("--tool", help="tool name for tools/call (only this tool is called)")
    p.add_argument("--required-scope", help="scope the tool requires")
    p.add_argument(
        "--requested-scope",
        help="deliberately narrowed scope sent to the token endpoint (must omit required-scope)",
    )
    p.add_argument(
        "--grant-type",
        default=FIXTURE_GRANT,
        help="token grant_type (default: client_credentials)",
    )
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument(
        "--json",
        action="store_true",
        help="emit a single JSON object on stdout (CI-friendly)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)

    if args.fixture:
        result = run_fixture_mode(args.fixture)
        print_result(result, as_json=args.json)
        return int(result["exit_code"])

    missing = [
        name
        for name, val in (
            ("--mcp-url", args.mcp_url),
            ("--tool", args.tool),
            ("--required-scope", args.required_scope),
            ("--requested-scope", args.requested_scope),
        )
        if not val
    ]
    # client creds required unless discovery can DCR — still need mcp-url etc.
    if missing:
        print("usage error: missing %s" % ", ".join(missing), file=sys.stderr)
        return EXIT_USAGE

    skip = bool(args.token_endpoint and args.client_id and args.client_secret is not None)
    if not skip and not (args.client_id and args.client_secret is not None):
        # discovery may DCR; allowed
        pass
    if skip and args.client_secret is None:
        print("usage error: --client-secret required with --token-endpoint", file=sys.stderr)
        return EXIT_USAGE

    result = run_scope_check(
        mcp_url=args.mcp_url,
        tool=args.tool,
        required_scope=args.required_scope,
        requested_scope=args.requested_scope,
        client_id=args.client_id,
        client_secret=args.client_secret,
        token_endpoint=args.token_endpoint,
        grant_type=args.grant_type,
        timeout=args.timeout,
        skip_discovery=skip,
    )
    print_result(result, as_json=args.json)
    return int(result["exit_code"])


if __name__ == "__main__":
    sys.exit(main())
