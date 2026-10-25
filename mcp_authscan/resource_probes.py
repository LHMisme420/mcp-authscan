"""Resource endpoint probes for MCP servers."""

import requests
from typing import Tuple, Optional
from mcp_authscan.oauth_probes_v2 import ProbeRecord

RESOURCE_PROBE_SET_VERSION = "1.0.2"


def run_resource_probes(target_url: str) -> list:
    """Run all 5 resource endpoint probes. Return list of ProbeRecord."""
    records = []
    
    preflight_pass, preflight_msg = probe_mcp_preflight(target_url)
    preflight_record = ProbeRecord(
        probe_id="mcp-preflight",
        name="mcp-preflight",
        status="PASS" if preflight_pass else "FAIL",
        detail=preflight_msg,
        severity="HIGH" if not preflight_pass else None,
        endpoint=target_url
    )
    records.append(preflight_record)
    
    if not preflight_pass:
        for probe_name in ["anon-initialize", "anon-tools-list", "endpoint-cors", "auth-challenge"]:
            excluded = ProbeRecord(
                probe_id=probe_name,
                name=probe_name,
                status="EXCLUDED",
                prerequisite_met=False,
                detail="mcp-preflight failed",
                endpoint=target_url
            )
            records.append(excluded)
        return records
    
    anon_init_fail, anon_init_msg = probe_anon_initialize(target_url)
    records.append(ProbeRecord(
        probe_id="anon-initialize",
        name="anon-initialize",
        status="FAIL" if anon_init_fail else "PASS",
        detail=anon_init_msg,
        severity="HIGH" if anon_init_fail else None,
        endpoint=target_url
    ))
    
    anon_tools_fail, anon_tools_msg = probe_anon_tools_list(target_url)
    records.append(ProbeRecord(
        probe_id="anon-tools-list",
        name="anon-tools-list",
        status="FAIL" if anon_tools_fail else "PASS",
        detail=anon_tools_msg,
        severity="CRITICAL" if anon_tools_fail else None,
        endpoint=target_url
    ))
    
    cors_fail, cors_severity, cors_msg = probe_endpoint_cors(target_url)
    records.append(ProbeRecord(
        probe_id="endpoint-cors",
        name="endpoint-cors",
        status="FAIL" if cors_fail else "PASS",
        detail=cors_msg,
        severity=cors_severity if cors_fail else None,
        endpoint=target_url
    ))
    
    auth_fail, auth_msg = probe_auth_challenge(target_url)
    records.append(ProbeRecord(
        probe_id="auth-challenge",
        name="auth-challenge",
        status="FAIL" if auth_fail else "PASS",
        detail=auth_msg,
        severity="MEDIUM" if auth_fail else None,
        endpoint=target_url
    ))
    
    return records


def probe_mcp_preflight(target_url: str) -> Tuple[bool, str]:
    """POST /initialize with empty JSON-RPC, no auth. PASS if we get any JSON-RPC response or 401/403."""
    try:
        payload = {"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code in [401, 403]:
            www_auth = response.headers.get("WWW-Authenticate")
            if not www_auth:
                return False, f"{response.status_code} without WWW-Authenticate: not an authenticated API"
            if "resource_metadata" in www_auth:
                return True, f"MCP endpoint protected (resource_metadata present)"
            return True, f"MCP endpoint protected (requires authentication)"
        
        try:
            data = response.json()
            # Must have jsonrpc field to be MCP JSON-RPC
            if "jsonrpc" in data:
                return True, "MCP endpoint responds to JSON-RPC"
        except:
            pass
        
        return False, f"No JSON-RPC response (HTTP {response.status_code})"
    except Exception as e:
        return False, f"Preflight error: {str(e)}"


def probe_anon_initialize(target_url: str) -> Tuple[bool, str]:
    """POST /initialize unauthenticated, FAIL if serverInfo/capabilities returned."""
    try:
        payload = {"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code in [401, 403]:
            return False, f"Correctly returned {response.status_code}"
        
        data = response.json()
        if "result" in data and data["result"]:
            result = data["result"]
            if "serverInfo" in result or "capabilities" in result:
                return True, "Unauthenticated initialize returned serverInfo/capabilities"
        
        return False, "No serverInfo/capabilities in response"
    except Exception as e:
        return False, f"initialize error: {str(e)}"


def probe_anon_tools_list(target_url: str) -> Tuple[bool, str]:
    """POST /tools/list unauthenticated, FAIL if tools array is non-empty."""
    try:
        payload = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code in [401, 403]:
            return False, f"Correctly returned {response.status_code}"
        
        data = response.json()
        if "result" in data and data["result"]:
            result = data["result"]
            if "tools" in result and isinstance(result["tools"], list) and len(result["tools"]) > 0:
                tool_names = [t.get("name", "unknown") for t in result["tools"]]
                return True, f"Unauthenticated tools/list returned {len(tool_names)} tools: {', '.join(tool_names[:3])}"
        
        return False, "No tools in response"
    except Exception as e:
        return False, f"tools/list error: {str(e)}"


def probe_endpoint_cors(target_url: str) -> Tuple[bool, str, Optional[str]]:
    """Send Origin header, FAIL if Allow-Origin echoes it or is *."""
    try:
        headers = {"Origin": "https://boardy.invalid"}
        payload = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, headers=headers, timeout=5, verify=True)
        
        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        
        if allow_origin and (allow_origin == "*" or allow_origin == "https://boardy.invalid"):
            severity = "CRITICAL" if allow_credentials else "MODERATE"
            return True, f"CORS misconfigured: Allow-Origin={allow_origin} (Credentials={allow_credentials})", severity
        
        return False, "CORS properly restricted", None
    except Exception as e:
        return False, f"CORS error: {str(e)}", None


def probe_auth_challenge(target_url: str) -> Tuple[bool, str]:
    """Send unauthenticated request, expect 401. FAIL if no WWW-Authenticate."""
    try:
        payload = {"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": 1}
        response = requests.post(target_url, json=payload, timeout=5, verify=True)
        
        if response.status_code == 401:
            www_auth = response.headers.get("WWW-Authenticate")
            if not www_auth:
                return True, "401 response lacks WWW-Authenticate header"
            return False, f"Correctly challenges with: {www_auth}"
        
        return False, f"Expected 401, got {response.status_code}"
    except Exception as e:
        return False, f"auth-challenge error: {str(e)}"
