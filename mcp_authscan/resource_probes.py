"""Resource endpoint probes for MCP servers."""

import json
import requests
import hashlib
from typing import Any, List
from mcp_authscan.oauth_probes_v2 import ProbeRecord

RESOURCE_PROBE_SET_VERSION = "1.0.2"


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
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code in [401, 403]:
            www_auth = response.headers.get("WWW-Authenticate")
            if not www_auth:
                return ProbeRecord(
                    probe_id="mcp-preflight",
                    name="mcp-preflight",
                    status="FAIL",
                    http_status=response.status_code,
                    headers_observed=dict(response.headers),
                    detail=f"{response.status_code} without WWW-Authenticate: not an authenticated API",
                    severity="HIGH",
                    endpoint=target_url
                )
            if "resource_metadata" in www_auth:
                return ProbeRecord(
                    probe_id="mcp-preflight",
                    name="mcp-preflight",
                    status="PASS",
                    http_status=response.status_code,
                    headers_observed=dict(response.headers),
                    detail="MCP endpoint protected (resource_metadata present)",
                    endpoint=target_url
                )
            return ProbeRecord(
                probe_id="mcp-preflight",
                name="mcp-preflight",
                status="PASS",
                http_status=response.status_code,
                headers_observed=dict(response.headers),
                detail="MCP endpoint protected (requires authentication)",
                endpoint=target_url
            )
        
        try:
            data = response.json()
            if "jsonrpc" in data:
                return ProbeRecord(
                    probe_id="mcp-preflight",
                    name="mcp-preflight",
                    status="PASS",
                    http_status=response.status_code,
                    detail="MCP endpoint responds to JSON-RPC",
                    endpoint=target_url
                )
        except:
            pass
        
        return ProbeRecord(
            probe_id="mcp-preflight",
            name="mcp-preflight",
            status="FAIL",
            http_status=response.status_code,
            detail=f"No JSON-RPC response (HTTP {response.status_code})",
            severity="HIGH",
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
            detail=f"Connection refused: {str(e)}",
            endpoint=target_url
        )
    except Exception as e:
        return ProbeRecord(
            probe_id="mcp-preflight",
            name="mcp-preflight",
            status="NOT_OBSERVED",
            detail=f"Preflight error: {str(e)}",
            endpoint=target_url
        )


def probe_anon_initialize(target_url: str) -> ProbeRecord:
    """POST /initialize unauthenticated, FAIL if serverInfo/capabilities returned."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code in [401, 403]:
            return ProbeRecord(
                probe_id="anon-initialize",
                name="anon-initialize",
                status="PASS",
                http_status=response.status_code,
                headers_observed=dict(response.headers),
                detail=f"Correctly returned {response.status_code}",
                endpoint=target_url
            )
        
        data = response.json()
        if "result" in data and data["result"]:
            result = data["result"]
            if "serverInfo" in result or "capabilities" in result:
                return ProbeRecord(
                    probe_id="anon-initialize",
                    name="anon-initialize",
                    status="FAIL",
                    http_status=response.status_code,
                    headers_observed=dict(response.headers),
                    body_excerpt=json.dumps(data)[:500],
                    detail="Unauthenticated initialize returned serverInfo/capabilities",
                    severity="HIGH",
                    endpoint=target_url
                )
        
        if "error" in data:
            return ProbeRecord(
                probe_id="anon-initialize",
                name="anon-initialize",
                status="PASS",
                http_status=response.status_code,
                detail=f"Correctly returned error",
                endpoint=target_url
            )
        
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            http_status=response.status_code,
            detail="No serverInfo/capabilities in response",
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
    except requests.exceptions.ConnectionError as e:
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            detail=f"Connection refused: {str(e)}",
            endpoint=target_url
        )
    except Exception as e:
        return ProbeRecord(
            probe_id="anon-initialize",
            name="anon-initialize",
            status="NOT_OBSERVED",
            detail=f"initialize error: {str(e)}",
            endpoint=target_url
        )


def probe_anon_tools_list(target_url: str) -> ProbeRecord:
    """POST /tools/list unauthenticated, FAIL if tools array is non-empty."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code in [401, 403]:
            return ProbeRecord(
                probe_id="anon-tools-list",
                name="anon-tools-list",
                status="PASS",
                http_status=response.status_code,
                headers_observed=dict(response.headers),
                detail=f"Correctly returned {response.status_code}",
                endpoint=target_url
            )
        
        data = response.json()
        if "result" in data and data["result"]:
            result = data["result"]
            if "tools" in result and isinstance(result["tools"], list) and len(result["tools"]) > 0:
                tool_names = [t.get("name", "unknown") for t in result["tools"]]
                first_three = ", ".join(tool_names[:3])
                body_hash = hashlib.sha256(json.dumps(data).encode()).hexdigest()
                return ProbeRecord(
                    probe_id="anon-tools-list",
                    name="anon-tools-list",
                    status="FAIL",
                    http_status=response.status_code,
                    headers_observed=dict(response.headers),
                    body_excerpt=json.dumps(data)[:500],
                    body_sha256=body_hash,
                    detail=f"Unauthenticated tools/list returned {len(tool_names)} tools: {first_three}",
                    severity="CRITICAL",
                    endpoint=target_url
                )
        
        if "error" in data:
            return ProbeRecord(
                probe_id="anon-tools-list",
                name="anon-tools-list",
                status="PASS",
                http_status=response.status_code,
                detail=f"Correctly returned error",
                endpoint=target_url
            )
        
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            http_status=response.status_code,
            detail="No tools in response",
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
    except requests.exceptions.ConnectionError as e:
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            detail=f"Connection refused: {str(e)}",
            endpoint=target_url
        )
    except Exception as e:
        return ProbeRecord(
            probe_id="anon-tools-list",
            name="anon-tools-list",
            status="NOT_OBSERVED",
            detail=f"tools/list error: {str(e)}",
            endpoint=target_url
        )


def probe_endpoint_cors(target_url: str) -> ProbeRecord:
    """Send Origin header, FAIL if Allow-Origin echoes it or is *."""
    try:
        headers = {"Origin": "https://boardy.invalid"}
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, headers=headers, timeout=5, verify=True)
        
        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        vary = response.headers.get("Vary", "")
        
        if allow_origin:
            if allow_origin == "*" or allow_origin == "https://boardy.invalid":
                severity = "CRITICAL" if allow_credentials else "MODERATE"
                return ProbeRecord(
                    probe_id="endpoint-cors",
                    name="endpoint-cors",
                    status="FAIL",
                    http_status=response.status_code,
                    headers_observed={
                        "Access-Control-Allow-Origin": allow_origin,
                        "Access-Control-Allow-Credentials": str(allow_credentials),
                        "Vary": vary
                    },
                    detail=f"CORS misconfigured: Allow-Origin={allow_origin} (Credentials={allow_credentials})",
                    severity=severity,
                    endpoint=target_url
                )
        
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="PASS",
            http_status=response.status_code,
            headers_observed={
                "Access-Control-Allow-Origin": allow_origin or "absent",
                "Access-Control-Allow-Credentials": str(allow_credentials)
            },
            detail="CORS properly restricted",
            endpoint=target_url
        )
    except requests.exceptions.Timeout:
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="NOT_OBSERVED",
            detail="CORS probe timeout",
            endpoint=target_url
        )
    except requests.exceptions.ConnectionError as e:
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="NOT_OBSERVED",
            detail=f"Connection refused: {str(e)}",
            endpoint=target_url
        )
    except Exception as e:
        return ProbeRecord(
            probe_id="endpoint-cors",
            name="endpoint-cors",
            status="NOT_OBSERVED",
            detail=f"CORS probe error: {str(e)}",
            endpoint=target_url
        )


def probe_auth_challenge(target_url: str) -> ProbeRecord:
    """Send unauthenticated request, expect 401. FAIL if no WWW-Authenticate."""
    try:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code == 401:
            www_auth = response.headers.get("WWW-Authenticate")
            if not www_auth:
                return ProbeRecord(
                    probe_id="auth-challenge",
                    name="auth-challenge",
                    status="FAIL",
                    http_status=response.status_code,
                    headers_observed=dict(response.headers),
                    detail="401 response lacks WWW-Authenticate header",
                    severity="MEDIUM",
                    endpoint=target_url
                )
            return ProbeRecord(
                probe_id="auth-challenge",
                name="auth-challenge",
                status="PASS",
                http_status=response.status_code,
                headers_observed=dict(response.headers),
                detail=f"Correctly challenges with: {www_auth}",
                endpoint=target_url
            )
        
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            http_status=response.status_code,
            detail=f"Expected 401 challenge, got {response.status_code}",
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
    except requests.exceptions.ConnectionError as e:
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            detail=f"Connection refused: {str(e)}",
            endpoint=target_url
        )
    except Exception as e:
        return ProbeRecord(
            probe_id="auth-challenge",
            name="auth-challenge",
            status="NOT_OBSERVED",
            detail=f"auth-challenge error: {str(e)}",
            endpoint=target_url
        )
