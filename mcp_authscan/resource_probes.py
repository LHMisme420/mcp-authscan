"""Resource endpoint probes for MCP servers."""

import json
import requests
import hashlib
from typing import Any, List, Tuple
from mcp_authscan.oauth_probes_v2 import ProbeRecord

RESOURCE_PROBE_SET_VERSION = "2026.10.28"

# Egress guard: restrict outbound to target host only
from mcp_authscan.http_headers import Headers


def _egress_guard_fetch(target_url: str, payload: dict, headers: dict | None = None, timeout: int = 5) -> Tuple[int, dict, bytes]:
    """POST using the existing OAuth egress guard."""
    from urllib.request import Request
    from mcp_authscan import oauth_probes_v2 as oauth

    request_headers = {"Content-Type": "application/json"}
    request_headers.update(headers or {})

    req = Request(
        target_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=request_headers,
        method="POST",
    )
    return oauth._egress_guard(
        req,
        timeout=timeout,
        allow_private=oauth.ALLOW_PRIVATE_TARGETS,
    )


def run_resource_probes(target_url: str) -> List[ProbeRecord]:
    """Run all 5 resource endpoint probes. Return list of ProbeRecord."""
    records = []
    
    # Run all probes, each handles its own errors
    records.append(probe_mcp_preflight(target_url))
    records.append(probe_anon_initialize(target_url))
    records.append(probe_anon_tools_list(target_url))
    records.append(probe_endpoint_cors(target_url))
    records.append(probe_auth_challenge(target_url))
    
    return records


def probe_mcp_preflight(target_url: str) -> ProbeRecord:
    """POST /initialize with empty JSON-RPC, no auth. PASS if we get 401/403 with WWW-Authenticate."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}
        status_code, headers, body_bytes = _egress_guard_fetch(target_url, payload)
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        # 5xx: cannot assess
        if status_code >= 500:
            return ProbeRecord(
                probe_id="mcp-preflight",
                name="mcp-preflight",
                status="NOT_OBSERVED",
                http_status=status_code,
                detail=f"Server error {status_code}; cannot assess",
                endpoint=target_url
            )

        # 401/403: a live, protected MCP endpoint only when the challenge is Bearer.
        # Any other scheme, or no WWW-Authenticate header, is not demonstrated.
        if status_code in [401, 403]:
            www_auth = headers.get("WWW-Authenticate", "")
            scheme = www_auth.split()[0].rstrip(",") if www_auth.split() else ""
            if scheme.lower() == "bearer":
                return ProbeRecord(
                    probe_id="mcp-preflight",
                    name="mcp-preflight",
                    status="PASS",
                    http_status=status_code,
                    headers_observed={"WWW-Authenticate": www_auth[:100]},
                    body_sha256=body_hash,
                    detail="MCP endpoint protected (Bearer challenge present)",
                    endpoint=target_url
                )
            return ProbeRecord(
                probe_id="mcp-preflight",
                name="mcp-preflight",
                status="NOT_OBSERVED",
                http_status=status_code,
                headers_observed={"WWW-Authenticate": www_auth[:100] if www_auth else "absent"},
                body_sha256=body_hash,
                detail=f"{status_code} without a Bearer challenge (WWW-Authenticate scheme: {scheme or 'absent'}); cannot confirm MCP OAuth endpoint",
                endpoint=target_url
            )

        # 2xx: check for JSON-RPC
        if 200 <= status_code < 300:
            try:
                data = json.loads(body_bytes.decode('utf-8', errors='ignore'))
                if isinstance(data, dict) and ("jsonrpc" in data or ("id" in data and ("result" in data or "error" in data))):
                    return ProbeRecord(
                        probe_id="mcp-preflight",
                        name="mcp-preflight",
                        status="FAIL",
                        http_status=status_code,
                        body_sha256=body_hash,
                        detail="Unauthenticated initialize succeeded (no WWW-Authenticate): endpoint accepts requests without credentials",
                        severity="HIGH",
                        endpoint=target_url
                    )
            except (ValueError, AttributeError, TypeError, UnicodeDecodeError):
                pass

            # 2xx but not MCP JSON-RPC
            return ProbeRecord(
                probe_id="mcp-preflight",
                name="mcp-preflight",
                status="NOT_OBSERVED",
                http_status=status_code,
                body_sha256=body_hash,
                detail="Response is not MCP JSON-RPC",
                endpoint=target_url
            )

        # Other status codes: cannot assess
        return ProbeRecord(
            probe_id="mcp-preflight",
            name="mcp-preflight",
            status="NOT_OBSERVED",
            http_status=status_code,
            body_sha256=body_hash,
            detail=f"Unexpected HTTP {status_code}; cannot assess MCP compliance",
            endpoint=target_url
        )
    except requests.exceptions.Timeout:
        return ProbeRecord(
            probe_id="mcp-preflight",
            name="mcp-preflight",
            status="NOT_OBSERVED",
            detail="Request timeout",
            endpoint=target_url
        )
    except requests.exceptions.ConnectionError as e:
        return ProbeRecord(
            probe_id="mcp-preflight",
            name="mcp-preflight",
            status="NOT_OBSERVED",
            detail=f"Connection refused",
            endpoint=target_url
        )
    except Exception as e:
        return ProbeRecord(
            probe_id="mcp-preflight",
            name="mcp-preflight",
            status="NOT_OBSERVED",
            detail=f"Preflight error",
            endpoint=target_url
        )


def probe_anon_initialize(target_url: str) -> ProbeRecord:
    """POST /initialize unauthenticated, FAIL if serverInfo/capabilities returned."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}
        status_code, headers, body_bytes = _egress_guard_fetch(target_url, payload)
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        # 5xx: cannot assess
        if status_code >= 500:
            return ProbeRecord(
                probe_id="anon-initialize",
                name="anon-initialize",
                status="NOT_OBSERVED",
                http_status=status_code,
                detail=f"Server error {status_code}; cannot assess",
                endpoint=target_url
            )

        # 401/403: correct behavior
        if status_code in [401, 403]:
            return ProbeRecord(
                probe_id="anon-initialize",
                name="anon-initialize",
                status="PASS",
                http_status=status_code,
                body_sha256=body_hash,
                detail=f"Correctly rejected unauthenticated request",
                endpoint=target_url
            )

        # Parse JSON-RPC response
        try:
            data = json.loads(body_bytes.decode('utf-8', errors='ignore'))
        except (ValueError, UnicodeDecodeError):
            # Non-JSON response at 2xx: cannot assess
            return ProbeRecord(
                probe_id="anon-initialize",
                name="anon-initialize",
                status="NOT_OBSERVED",
                http_status=status_code,
                body_sha256=body_hash,
                detail="Response is not JSON-RPC",
                endpoint=target_url
            )

        # Check for vulnerability: serverInfo or capabilities exposed
        if isinstance(data, dict) and "result" in data and data["result"]:
            result = data["result"]
            if isinstance(result, dict) and ("serverInfo" in result or "capabilities" in result):
                return ProbeRecord(
                    probe_id="anon-initialize",
                    name="anon-initialize",
                    status="FAIL",
                    http_status=status_code,
                    body_sha256=body_hash,
                    detail="Unauthenticated initialize returned serverInfo/capabilities: info leak confirmed",
                    severity="HIGH",
                    endpoint=target_url
                )

        # Check for error response: correct behavior
        if isinstance(data, dict) and "error" in data:
            return ProbeRecord(
                probe_id="anon-initialize",
                name="anon-initialize",
                status="NOT_OBSERVED",
                http_status=status_code,
                body_sha256=body_hash,
                detail="JSON-RPC error does not establish authentication enforcement",
                endpoint=target_url
            )

        # No serverInfo/capabilities and no error: cannot assess
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            http_status=status_code,
            body_sha256=body_hash,
            detail="No serverInfo/capabilities or error in response",
            endpoint=target_url
        )
    except requests.exceptions.Timeout:
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            detail="Request timeout",
            endpoint=target_url
        )
    except requests.exceptions.ConnectionError:
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            detail="Connection refused",
            endpoint=target_url
        )
    except Exception:
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            detail="Request error",
            endpoint=target_url
        )


def probe_anon_tools_list(target_url: str) -> ProbeRecord:
    """POST /tools/list unauthenticated, FAIL if tools array is non-empty."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        status_code, headers, body_bytes = _egress_guard_fetch(target_url, payload)
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        # 5xx: cannot assess
        if status_code >= 500:
            return ProbeRecord(
                probe_id="anon-tools-list",
                name="anon-tools-list",
                status="NOT_OBSERVED",
                http_status=status_code,
                detail=f"Server error {status_code}; cannot assess",
                endpoint=target_url
            )

        # 401/403: correct behavior
        if status_code in [401, 403]:
            return ProbeRecord(
                probe_id="anon-tools-list",
                name="anon-tools-list",
                status="PASS",
                http_status=status_code,
                body_sha256=body_hash,
                detail="Correctly rejected unauthenticated request",
                endpoint=target_url
            )

        # Parse JSON-RPC response
        try:
            data = json.loads(body_bytes.decode('utf-8', errors='ignore'))
        except (ValueError, UnicodeDecodeError):
            # Non-JSON response at 2xx: cannot assess
            return ProbeRecord(
                probe_id="anon-tools-list",
                name="anon-tools-list",
                status="NOT_OBSERVED",
                http_status=status_code,
                body_sha256=body_hash,
                detail="Response is not JSON-RPC",
                endpoint=target_url
            )

        # Check for vulnerability: tools exposed
        if isinstance(data, dict) and "result" in data and data["result"]:
            result = data["result"]
            if isinstance(result, dict) and "tools" in result and isinstance(result["tools"], list):
                if len(result["tools"]) > 0:
                    tool_names = [t.get("name", "unknown") for t in result["tools"] if isinstance(t, dict)]
                    return ProbeRecord(
                        probe_id="anon-tools-list",
                        name="anon-tools-list",
                        status="FAIL",
                        http_status=status_code,
                        body_sha256=body_hash,
                        detail=f"Unauthenticated tools/list returned {len(tool_names)} tools: enumeration confirmed",
                        severity="MEDIUM",
                        endpoint=target_url
                    )

        # Check for error response: correct behavior
        if isinstance(data, dict) and "error" in data:
            return ProbeRecord(
                probe_id="anon-tools-list",
                name="anon-tools-list",
                status="NOT_OBSERVED",
                http_status=status_code,
                body_sha256=body_hash,
                detail="JSON-RPC error does not establish authentication enforcement",
                endpoint=target_url
            )

        # No tools or empty tools list: cannot assess
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            http_status=status_code,
            body_sha256=body_hash,
            detail="No tools in response or unable to determine tool list",
            endpoint=target_url
        )
    except requests.exceptions.Timeout:
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            detail="Request timeout",
            endpoint=target_url
        )
    except requests.exceptions.ConnectionError:
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            detail="Connection refused",
            endpoint=target_url
        )
    except Exception:
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            detail="Request error",
            endpoint=target_url
        )


def probe_endpoint_cors(target_url: str) -> ProbeRecord:
    """Send Origin header, FAIL if Allow-Origin echoes it or is wildcard."""
    try:
        origin_sent = "https://boardy.invalid"
        headers = {"Origin": origin_sent}
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        status_code, resp_headers, body_bytes = _egress_guard_fetch(target_url, payload, headers=headers)
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        # 5xx: cannot assess CORS
        if status_code >= 500:
            return ProbeRecord(
                probe_id="endpoint-cors",
                name="endpoint-cors",
                status="NOT_OBSERVED",
                http_status=status_code,
                detail="Server error; cannot assess CORS",
                endpoint=target_url
            )

        # Extract CORS headers
        allow_origin = resp_headers.get("Access-Control-Allow-Origin", "")
        allow_credentials = resp_headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        # Absent ACAO: endpoint not configured for CORS, cannot assess
        if not allow_origin:
            return ProbeRecord(
                probe_id="endpoint-cors",
                name="endpoint-cors",
                status="NOT_OBSERVED",
                http_status=status_code,
                body_sha256=body_hash,
                detail="No CORS headers; endpoint not configured for CORS",
                endpoint=target_url
            )

        # Wildcard or echo: FAIL
        if allow_origin == "*" or allow_origin == origin_sent:
            # Credentialed cross-origin is CRITICAL; non-credentialed is HIGH
            severity = "CRITICAL" if allow_credentials else "HIGH"
            return ProbeRecord(
                probe_id="endpoint-cors",
                name="endpoint-cors",
                status="FAIL",
                http_status=status_code,
                headers_observed={
                    "Access-Control-Allow-Origin": allow_origin,
                    "Access-Control-Allow-Credentials": str(allow_credentials)
                },
                body_sha256=body_hash,
                detail=f"CORS misconfigured: Allow-Origin={allow_origin}" + (" with credentials=true" if allow_credentials else ""),
                severity=severity,
                endpoint=target_url
            )

        # Specific origin declared: PASS
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="PASS",
            http_status=status_code,
            headers_observed={
                "Access-Control-Allow-Origin": allow_origin,
                "Access-Control-Allow-Credentials": str(allow_credentials)
            },
            body_sha256=body_hash,
            detail="CORS properly restricted to specific origin",
            endpoint=target_url
        )
    except requests.exceptions.Timeout:
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="NOT_OBSERVED",
            detail="Request timeout",
            endpoint=target_url
        )
    except requests.exceptions.ConnectionError:
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="NOT_OBSERVED",
            detail="Connection refused",
            endpoint=target_url
        )
    except Exception:
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="NOT_OBSERVED",
            detail="Request error",
            endpoint=target_url
        )


def probe_auth_challenge(target_url: str) -> ProbeRecord:
    """Send unauthenticated request, expect 401. FAIL if no WWW-Authenticate."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        status_code, headers, body_bytes = _egress_guard_fetch(target_url, payload)
        body_hash = hashlib.sha256(body_bytes).hexdigest()

        # 5xx: cannot assess auth
        if status_code >= 500:
            return ProbeRecord(
                probe_id="auth-challenge",
                name="auth-challenge",
                status="NOT_OBSERVED",
                http_status=status_code,
                detail="Server error; cannot assess authentication",
                endpoint=target_url
            )

        # 401: protected on a Bearer challenge alone. A Bearer challenge demonstrates
        # the server requires an OAuth bearer credential; whether it also advertises
        # resource metadata is a separate property, not a protection failure. Any
        # non-Bearer scheme, or no header, is not demonstrated: NOT_OBSERVED, with the
        # scheme seen named in the reason.
        if status_code == 401:
            www_auth = headers.get("WWW-Authenticate", "")
            scheme = www_auth.split()[0].rstrip(",") if www_auth.split() else ""
            seen = scheme if scheme else "absent"
            if scheme.lower() == "bearer":
                return ProbeRecord(
                    probe_id="auth-challenge",
                    name="auth-challenge",
                    status="PASS",
                    http_status=status_code,
                    headers_observed={"WWW-Authenticate": www_auth[:100]},
                    body_sha256=body_hash,
                    detail="Correctly challenges with Bearer authentication",
                    endpoint=target_url
                )
            return ProbeRecord(
                probe_id="auth-challenge",
                name="auth-challenge",
                status="NOT_OBSERVED",
                http_status=status_code,
                headers_observed={"WWW-Authenticate": www_auth[:100] if www_auth else "absent"},
                body_sha256=body_hash,
                detail=f"401 challenge scheme '{seen}' is not Bearer; cannot confirm MCP OAuth protection",
                endpoint=target_url
            )

        # Not 401: cannot assess authentication challenge
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            http_status=status_code,
            body_sha256=body_hash,
            detail=f"Expected 401 challenge, got {status_code}; cannot assess",
            endpoint=target_url
        )
    except requests.exceptions.Timeout:
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            detail="Request timeout",
            endpoint=target_url
        )
    except requests.exceptions.ConnectionError:
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            detail="Connection refused",
            endpoint=target_url
        )
    except Exception:
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            detail="Request error",
            endpoint=target_url
        )
