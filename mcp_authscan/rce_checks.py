"""Opt-in detectors for MCP RCE-precondition classes (OX Security, April 2026).

Two safe, non-exploitative checks that the main scanner runs under
`--checks all`, and that the research CLI (research/mcp_stdio_rce/detector.py)
reuses:

  * Unauthenticated MCP config/registration endpoint (config -> STDIO-spawn
    RCE class, e.g. LiteLLM CVE-2026-30623). Never registers a server or submits
    a command to run.
  * Missing Host/Origin validation (DNS-rebinding precondition, e.g. MCP Java
    SDK CVE-2026-35568). Sends only a foreign Host/Origin; makes no tool calls.

Authorization: run these only against a server you operate or are explicitly
authorized to test. Reachability is not permission.
"""
import json

import requests

from .scanner import Check, RiskLevel

LISTING_PATHS = ("/mcp/servers", "/config/mcp", "/api/mcp/servers", "/v1/mcp/servers")
REGISTER_PATHS = ("/mcp/servers", "/api/mcp/servers", "/v1/mcp/servers")
REGISTRY_MARKERS = ("servers", "mcpservers", "command", "stdio")
REBIND_PATHS = ("/mcp", "/sse", "/mcp/servers", "/")


def _looks_like_registry(text):
    low = text[:8192].lower()
    if not any(marker in low for marker in REGISTRY_MARKERS):
        return False
    try:
        return isinstance(json.loads(text), (dict, list))
    except ValueError:
        return False


def detect_unauth_mcp_config(base_url, timeout=5, session=None):
    """Return a finding dict if an unauthenticated config endpoint is found, else None.

    Signal A: a config/registry listing served without auth.
    Signal B: a registration endpoint that answers an empty/malformed POST with a
    validation error (400) instead of 401/403 -- i.e. it processed an
    unauthenticated request. The empty body guarantees nothing is registered or
    executed.
    """
    http = session or requests
    base = base_url.rstrip("/")
    evidence = []

    for path in LISTING_PATHS:
        try:
            resp = http.get(f"{base}{path}", timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code == 200 and _looks_like_registry(resp.text or ""):
            evidence.append(f"GET {path} -> 200 exposes MCP registry without auth")

    for path in REGISTER_PATHS:
        try:
            resp = http.post(f"{base}{path}", json={}, timeout=timeout)
        except requests.RequestException:
            continue
        if resp.status_code == 400:
            evidence.append(f"POST {path} -> 400 (processed unauthenticated request; auth not enforced)")

    if not evidence:
        return None
    return {
        "severity": "CRITICAL",
        "issue": "Unauthenticated MCP configuration/registration endpoint",
        "impact": "Class of OX Security config->STDIO-spawn RCE "
                  "(e.g. LiteLLM CVE-2026-30623).",
        "evidence": evidence,
        "remediation": "Require authentication on all MCP-config endpoints and "
                       "restrict registrable launchers to an allowlist.",
        "note": "Detection only -- no server was registered and no command was executed.",
    }


def detect_dns_rebinding_precondition(base_url, timeout=5, session=None):
    """Return a finding dict if Host/Origin are not pinned, else None.

    Sends a foreign Host + Origin to endpoints that already answer on the real
    host; if the server still processes them (instead of rejecting with
    400/403/421), it does not pin Host/Origin and a rebound browser could reach
    it. Makes no tool calls and changes no state.
    """
    http = session or requests
    base = base_url.rstrip("/")
    foreign_host, foreign_origin = "attacker.example", "https://evil.example"
    evidence = []
    for path in REBIND_PATHS:
        url = f"{base}{path}"
        try:
            baseline = http.get(url, timeout=timeout)
            probe = http.get(url, timeout=timeout,
                             headers={"Host": foreign_host, "Origin": foreign_origin})
        except requests.RequestException:
            continue
        if baseline.status_code >= 400:
            continue
        if probe.status_code in (400, 403, 421):
            continue
        if probe.status_code == baseline.status_code:
            note = f"{path}: foreign Host accepted (HTTP {probe.status_code})"
            if probe.headers.get("Access-Control-Allow-Origin") in ("*", foreign_origin):
                note += "; foreign Origin reflected in Access-Control-Allow-Origin"
            evidence.append(note)
    if not evidence:
        return None
    return {
        "severity": "HIGH",
        "issue": "Missing Host/Origin validation (DNS-rebinding precondition)",
        "impact": "DNS-rebinding family (e.g. MCP Java SDK CVE-2026-35568): a "
                  "rebound browser can reach this local/private MCP server and "
                  "make tool calls because Host/Origin are not pinned.",
        "evidence": evidence,
        "remediation": "Validate Host and Origin against an explicit allowlist "
                       "(127.0.0.1/localhost and known hostnames); reject others "
                       "with 403. Bind to loopback where external access is not needed.",
        "note": "Detection only -- no tool calls were made and no state changed.",
    }


# --- Check-object wrappers, so these flow through report/SARIF/fail-on ---

def check_unauth_mcp_config(base_url, timeout=5, session=None):
    finding = detect_unauth_mcp_config(base_url, timeout, session)
    desc = "Detects an unauthenticated MCP config/registration endpoint (config->STDIO-spawn RCE class)"
    if finding:
        return Check("Unauthenticated MCP Config Endpoint", desc, "/mcp/servers",
                     "GET/POST", RiskLevel.CRITICAL, False,
                     "; ".join(finding["evidence"]), finding["remediation"])
    return Check("Unauthenticated MCP Config Endpoint", desc, "/mcp/servers",
                 "GET/POST", RiskLevel.INFO, True,
                 "No unauthenticated MCP config/registration endpoint found",
                 "Keep MCP-config endpoints authenticated.")


def check_dns_rebinding(base_url, timeout=5, session=None):
    finding = detect_dns_rebinding_precondition(base_url, timeout, session)
    desc = "Detects missing Host/Origin pinning (DNS-rebinding precondition)"
    if finding:
        return Check("Host/Origin Validation (DNS Rebinding)", desc, "*", "GET",
                     RiskLevel.HIGH, False,
                     "; ".join(finding["evidence"]), finding["remediation"])
    return Check("Host/Origin Validation (DNS Rebinding)", desc, "*", "GET",
                 RiskLevel.INFO, True,
                 "Foreign Host/Origin rejected; Host/Origin appear validated",
                 "Validate Host/Origin against an allowlist; bind to loopback where possible.")
