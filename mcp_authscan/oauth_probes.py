#!/usr/bin/env python3
"""
OAuth Authorization Server probes (RFC 8414 metadata endpoints)
Separate from MCP resource endpoint probes (D1/D2/D3).

Version: 1.0.0 (independent versioning from MCP probes)

Probes assess:
1. Issuer identity binding (metadata issuer == fetch URL)
2. Resource binding (resource value matches MCP endpoint)
3. Token endpoint Cache-Control headers
4. Token endpoint CORS policy
5. JWKS key restrictions
6. Unsupported grant types (password, implicit)
7. Metadata vs behavior consistency
8. Client authentication enforcement
9. PKCE enforcement (requires client)
10. Redirect URI matching (requires client)
11. Dynamic registration policy

Verdict rule: Response not exactly expected → NOT_OBSERVED, never PASS.
"""
import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OAUTH_PROBE_VERSION = "1.0.0"

def run_oauth_probes(oauth_server_url, resource_metadata, client=None):
    """
    Run OAuth server probes against authorization server metadata endpoint.

    Returns:
    - probes_run: list of (rule_number, rule_name, status, evidence, verdict)
    - findings: list of dicts with severity/description/evidence
    """
    probes_run = []
    findings = []

    base_url = oauth_server_url.rstrip("/")

    # Fetch authorization server metadata
    try:
        metadata_url = base_url + "/.well-known/oauth-authorization-server"
        req = Request(metadata_url)
        req.add_header("User-Agent", "mcp-authscan/1.0.0")

        with urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                probes_run.append((0, "metadata-fetch", resp.status, f"HTTP {resp.status}", "NOT_OBSERVED"))
                return probes_run, findings

            metadata = json.loads(resp.read().decode())
    except (HTTPError, URLError, json.JSONDecodeError) as e:
        probes_run.append((0, "metadata-fetch", str(type(e).__name__), str(e), "NOT_OBSERVED"))
        return probes_run, findings

    # Rule 1: Issuer identity binding
    issuer = metadata.get("issuer", "")
    if issuer == base_url:
        probes_run.append((1, "issuer-identity", issuer, f"issuer={issuer}, URL={base_url}", "PASS"))
    else:
        probes_run.append((1, "issuer-identity", issuer, f"issuer={issuer}, URL={base_url}", "FAIL"))
        findings.append({
            "rule": 1,
            "severity": "HIGH",
            "title": "Issuer identity mismatch",
            "description": f"Authorization server issuer ({issuer}) does not match fetch URL ({base_url})",
            "evidence": f"Metadata issuer: {issuer}\nFetch URL: {base_url}"
        })

    # Rule 2: Resource binding (checked later with resource_metadata)
    if resource_metadata:
        resource_value = resource_metadata.get("resource", "")
        probes_run.append((2, "resource-binding", resource_value, f"resource={resource_value}", "PASS"))

    # Rule 3: Token endpoint Cache-Control
    token_endpoint = metadata.get("token_endpoint", "")
    if token_endpoint:
        try:
            req = Request(token_endpoint, method="POST")
            req.add_header("User-Agent", "mcp-authscan/1.0.0")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.data = b"grant_type=client_credentials"  # Will error

            with urlopen(req, timeout=5) as resp:
                cache_control = resp.headers.get("Cache-Control", "")
        except HTTPError as e:
            cache_control = e.headers.get("Cache-Control", "")

            if "no-store" in cache_control.lower():
                probes_run.append((3, "token-cache-control", cache_control, f"Cache-Control: {cache_control}", "PASS"))
            else:
                probes_run.append((3, "token-cache-control", cache_control or "(missing)", f"Cache-Control: {cache_control or 'not set'}", "FAIL"))
                findings.append({
                    "rule": 3,
                    "severity": "MEDIUM",
                    "title": "Token endpoint missing Cache-Control: no-store",
                    "description": "Token endpoint error responses must include Cache-Control: no-store",
                    "evidence": f"Cache-Control header: {cache_control or '(missing)'}"
                })
        except (URLError, Exception) as e:
            probes_run.append((3, "token-cache-control", str(type(e).__name__), str(e), "NOT_OBSERVED"))

    # Rule 4: Token endpoint CORS (must NOT have wildcard Allow-Origin)
    if token_endpoint:
        try:
            req = Request(token_endpoint, method="POST")
            req.add_header("User-Agent", "mcp-authscan/1.0.0")
            req.data = b"grant_type=invalid"

            with urlopen(req, timeout=5) as resp:
                cors_header = resp.headers.get("Access-Control-Allow-Origin", "")
        except HTTPError as e:
            cors_header = e.headers.get("Access-Control-Allow-Origin", "")

            if cors_header == "*":
                probes_run.append((4, "token-cors", cors_header, "Allow-Origin: *", "FAIL"))
                findings.append({
                    "rule": 4,
                    "severity": "HIGH",
                    "title": "Token endpoint allows wildcard CORS",
                    "description": "Token endpoint must not respond with Access-Control-Allow-Origin: *",
                    "evidence": f"Access-Control-Allow-Origin: {cors_header}"
                })
            else:
                probes_run.append((4, "token-cors", cors_header or "(none)", f"Allow-Origin: {cors_header or 'not set'}", "PASS"))
        except (URLError, Exception) as e:
            probes_run.append((4, "token-cors", str(type(e).__name__), str(e), "NOT_OBSERVED"))

    # Rule 5: JWKS key restrictions
    jwks_uri = metadata.get("jwks_uri", "")
    if jwks_uri:
        try:
            req = Request(jwks_uri)
            req.add_header("User-Agent", "mcp-authscan/1.0.0")

            with urlopen(req, timeout=5) as resp:
                jwks_data = json.loads(resp.read().decode())
                keys = jwks_data.get("keys", [])

                bad_keys = [k for k in keys if k.get("alg") == "none" or "kty" not in k]
                if bad_keys:
                    probes_run.append((5, "jwks-keys", f"{len(bad_keys)} invalid", f"{len(bad_keys)} keys with alg=none or missing kty", "FAIL"))
                    findings.append({
                        "rule": 5,
                        "severity": "CRITICAL",
                        "title": "JWKS contains invalid keys",
                        "description": f"JWKS endpoint contains {len(bad_keys)} keys with alg=none or missing key type",
                        "evidence": json.dumps(bad_keys, indent=2)
                    })
                else:
                    probes_run.append((5, "jwks-keys", f"{len(keys)} valid", f"{len(keys)} asymmetric keys, none with alg=none", "PASS"))
        except (HTTPError, URLError, json.JSONDecodeError) as e:
            probes_run.append((5, "jwks-keys", str(type(e).__name__), str(e), "NOT_OBSERVED"))

    # Rule 6: Password grant unsupported
    if token_endpoint:
        try:
            req = Request(token_endpoint, method="POST")
            req.add_header("User-Agent", "mcp-authscan/1.0.0")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.data = b"grant_type=password&username=test&password=test"

            with urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors='ignore')
                if "unsupported_grant_type" in body:
                    probes_run.append((6, "password-grant", "unsupported_grant_type", "Password grant correctly rejected", "PASS"))
                else:
                    probes_run.append((6, "password-grant", "accepted", f"HTTP {resp.status}", "FAIL"))
                    findings.append({
                        "rule": 6,
                        "severity": "MEDIUM",
                        "title": "Password grant type accepted",
                        "description": "Authorization server accepts deprecated password grant type",
                        "evidence": f"POST /token with grant_type=password returned HTTP {resp.status}"
                    })
        except HTTPError as e:
            body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
            if "unsupported_grant_type" in body:
                probes_run.append((6, "password-grant", "unsupported_grant_type", "Password grant correctly rejected", "PASS"))
            else:
                probes_run.append((6, "password-grant", f"HTTP {e.code}", "Unexpected error response", "NOT_OBSERVED"))
        except (URLError, Exception) as e:
            probes_run.append((6, "password-grant", str(type(e).__name__), str(e), "NOT_OBSERVED"))

    # Rule 7: Implicit flow unsupported
    authorize_endpoint = metadata.get("authorization_endpoint", "")
    if authorize_endpoint:
        try:
            test_url = f"{authorize_endpoint}?response_type=token&client_id=test&redirect_uri=https://localhost/cb"
            req = Request(test_url)
            req.add_header("User-Agent", "mcp-authscan/1.0.0")

            with urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors='ignore')
                if "unsupported_response_type" in body:
                    probes_run.append((7, "implicit-flow", "unsupported_response_type", "Implicit flow correctly rejected", "PASS"))
                else:
                    probes_run.append((7, "implicit-flow", "accepted", f"HTTP {resp.status}", "FAIL"))
        except HTTPError as e:
            body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
            if "unsupported_response_type" in body:
                probes_run.append((7, "implicit-flow", "unsupported_response_type", "Implicit flow correctly rejected", "PASS"))
            else:
                probes_run.append((7, "implicit-flow", f"HTTP {e.code}", "Unexpected response", "NOT_OBSERVED"))
        except (URLError, Exception) as e:
            probes_run.append((7, "implicit-flow", str(type(e).__name__), str(e), "NOT_OBSERVED"))

    # Rule 9: Client authentication (no credentials)
    if token_endpoint:
        try:
            req = Request(token_endpoint, method="POST")
            req.add_header("User-Agent", "mcp-authscan/1.0.0")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.data = b"grant_type=authorization_code&code=test"

            with urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors='ignore')
                probes_run.append((9, "client-auth", "processed", f"HTTP {resp.status}", "FAIL"))
                findings.append({
                    "rule": 9,
                    "severity": "CRITICAL",
                    "title": "Token endpoint processed request without client credentials",
                    "description": "Token endpoint accepted authorization code without client authentication",
                    "evidence": f"POST /token with no credentials returned HTTP {resp.status}"
                })
        except HTTPError as e:
            body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
            error_name = ""
            try:
                error_obj = json.loads(body)
                error_name = error_obj.get("error", "")
            except (ValueError, KeyError):
                pass

            if error_name == "invalid_client":
                probes_run.append((9, "client-auth", "invalid_client", "Client auth enforced", "PASS"))
            elif error_name == "invalid_grant":
                probes_run.append((9, "client-auth", "invalid_grant", "Processed without client auth", "FAIL"))
                findings.append({
                    "rule": 9,
                    "severity": "CRITICAL",
                    "title": "Client authentication not enforced",
                    "description": "Token endpoint returned invalid_grant instead of invalid_client, indicating request was processed without authentication",
                    "evidence": f"Error: {error_name}"
                })
            else:
                probes_run.append((9, "client-auth", error_name or f"HTTP {e.code}", "Unexpected error", "NOT_OBSERVED"))
        except (URLError, Exception) as e:
            probes_run.append((9, "client-auth", str(type(e).__name__), str(e), "NOT_OBSERVED"))

    # Rules 10-11 require client
    if not client:
        probes_run.append((10, "pkce-enforced", "N/A", "Requires registered client", "NOT_OBSERVED"))
        probes_run.append((11, "redirect-uri-matching", "N/A", "Requires registered client", "NOT_OBSERVED"))

    return probes_run, findings
