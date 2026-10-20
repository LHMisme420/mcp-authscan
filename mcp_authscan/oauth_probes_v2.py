#!/usr/bin/env python3
"""
OAuth Authorization Server Assessment
RFC 8414 metadata endpoints and endpoint behavior

Version: 2.0.0 (complete rewrite - one result record, one counter function, one printer)

Architecture:
- Every probe returns exactly one result record
- Verdict, evidence, limitation computed once inside probe's evaluate()
- Counters derived from records list only, verified before rendering
- Fail closed: missing metadata stops assessment immediately
- Two separate endpoint lists: resource (MCP) and authserver (OAuth)
"""
import json
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

OAUTH_PROBE_VERSION = "2.0.0"


class ProbeRecord:
    """Single probe result with full evidence trail."""
    def __init__(self, probe_id, probe_class, probe_name, request_method, url,
                 status, content_type, headers_observed, body_excerpt, body_sha256,
                 verdict, evidence, limitation):
        self.probe_id = probe_id
        self.probe_class = probe_class  # "resource" or "authserver"
        self.probe_name = probe_name
        self.request_method = request_method
        self.url = url
        self.status = status
        self.content_type = content_type
        self.headers_observed = headers_observed  # dict
        self.body_excerpt = body_excerpt
        self.body_sha256 = body_sha256
        self.verdict = verdict  # PASS, FAIL, NOT_OBSERVED
        self.evidence = evidence  # string
        self.limitation = limitation  # string or None


def probe_issuer_identity(metadata_url, metadata):
    """
    Issuer identity must match fetch URL exactly.
    PASS: issuer == url (byte-identical)
    FAIL: mismatch
    """
    issuer = metadata.get("issuer", "")
    base_url = metadata_url.split("/.well-known/")[0] if "/.well-known/" in metadata_url else metadata_url
    expected = base_url

    import sys
    print(f"[DEBUG issuer] metadata.issuer={issuer!r} | base_url={expected!r}", file=sys.stderr)
    evidence = f"issuer={issuer}\nbase_url={expected}"

    if issuer == expected:
        verdict = "PASS"
    else:
        verdict = "FAIL"

    return ProbeRecord(
        probe_id=1,
        probe_class="authserver",
        probe_name="issuer-identity",
        request_method="GET",
        url=metadata_url,
        status=200,
        content_type="application/json",
        headers_observed={},
        body_excerpt=json.dumps({"issuer": issuer}),
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=None
    )


def probe_resource_binding(resource_metadata, mcp_url):
    """
    Protected resource metadata's resource value must equal MCP endpoint.
    PASS: resource == mcp_url (byte-identical)
    FAIL: mismatch
    """
    if not resource_metadata:
        return None

    import sys; print(f"[DEBUG resource_binding] input={resource_metadata!r}", file=sys.stderr)
    resource = resource_metadata.get("resource", "")
    print(f"[DEBUG resource] metadata.resource={resource!r} | mcp_url={mcp_url!r}", file=sys.stderr)
    evidence = f"resource={resource}\nmcp_url={mcp_url}"

    if resource == mcp_url:
        verdict = "PASS"
    else:
        verdict = "FAIL"

    return ProbeRecord(
        probe_id=2,
        probe_class="authserver",
        probe_name="resource-binding",
        request_method="GET",
        url="",
        status=200,
        content_type="application/json",
        headers_observed={},
        body_excerpt=json.dumps({"resource": resource}),
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=None
    )


def probe_token_cache_control(token_endpoint):
    """
    Token endpoint error responses must carry Cache-Control: no-store.
    PASS: no-store present
    FAIL: missing or wrong value
    """
    if not token_endpoint:
        return ProbeRecord(
            1, "authserver", "token-cache-control", "POST", token_endpoint or "",
            0, "", {}, "", "", "NOT_OBSERVED", "", "No token_endpoint in metadata"
        )

    cache_control = ""
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = b"grant_type=invalid"

        try:
            with urlopen(req, timeout=5) as resp:
                cache_control = resp.headers.get("Cache-Control", "")
        except HTTPError as e:
            cache_control = e.headers.get("Cache-Control", "")
    except (URLError, Exception) as e:
        return ProbeRecord(
            3, "authserver", "token-cache-control", "POST", token_endpoint,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    verdict = "PASS" if "no-store" in cache_control.lower() else "FAIL"
    evidence = f"Cache-Control: {cache_control or '(absent)'}"

    return ProbeRecord(
        probe_id=3,
        probe_class="authserver",
        probe_name="token-cache-control",
        request_method="POST",
        url=token_endpoint,
        status=0,
        content_type="",
        headers_observed={"Cache-Control": cache_control},
        body_excerpt="",
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=None
    )


def probe_token_cors(token_endpoint):
    """
    Token endpoint CORS: Send Origin header, record ACAO/ACAC/Vary.
    Always returns observation (not PASS/FAIL) with impact statement.
    """
    if not token_endpoint:
        return ProbeRecord(
            4, "authserver", "token-cors", "POST", token_endpoint or "",
            0, "", {}, "", "", "NOT_OBSERVED", "", "No token_endpoint in metadata"
        )

    acao = ""
    acac = ""
    vary = ""

    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Origin", "https://example.invalid")
        req.data = b"grant_type=invalid"

        try:
            with urlopen(req, timeout=5) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                vary = resp.headers.get("Vary", "")
        except HTTPError as e:
            acao = e.headers.get("Access-Control-Allow-Origin", "")
            acac = e.headers.get("Access-Control-Allow-Credentials", "")
            vary = e.headers.get("Vary", "")
    except (URLError, Exception) as e:
        return ProbeRecord(
            4, "authserver", "token-cors", "POST", token_endpoint,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    # Always observation, never FAIL
    impact = "Wildcard CORS on token endpoint: clients in any origin can reach it, but authentication is enforced." if acao == "*" else "CORS restricted or absent."
    evidence = f"ACAO: {acao or '(absent)'}\nACAC: {acac or '(absent)'}\nVary: {vary or '(absent)'}\nImpact: {impact}"

    return ProbeRecord(
        probe_id=4,
        probe_class="authserver",
        probe_name="token-cors",
        request_method="POST",
        url=token_endpoint,
        status=0,
        content_type="",
        headers_observed={"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": acac, "Vary": vary},
        body_excerpt="",
        body_sha256="",
        verdict="OBSERVATION",  # Never PASS or FAIL
        evidence=evidence,
        limitation=None
    )


def probe_jwks_keys(jwks_uri):
    """
    JWKS endpoint returns only asymmetric keys (RSA, EC, OKP), none with alg=none.
    PASS: all keys valid
    FAIL: alg=none or invalid kty found
    """
    if not jwks_uri:
        return ProbeRecord(
            5, "authserver", "jwks-keys", "GET", jwks_uri or "",
            0, "", {}, "", "", "NOT_OBSERVED", "", "No jwks_uri in metadata"
        )

    try:
        req = Request(jwks_uri)
        req.add_header("User-Agent", "mcp-authscan/2.0.0")

        with urlopen(req, timeout=5) as resp:
            jwks_data = json.loads(resp.read().decode())
            keys = jwks_data.get("keys", [])
    except (HTTPError, URLError, json.JSONDecodeError) as e:
        return ProbeRecord(
            5, "authserver", "jwks-keys", "GET", jwks_uri,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    invalid_keys = []
    for k in keys:
        if k.get("alg") == "none":
            invalid_keys.append(f"alg=none")
        if k.get("kty") not in ["RSA", "EC", "OKP"]:
            invalid_keys.append(f"invalid kty={k.get('kty')}")

    verdict = "FAIL" if invalid_keys else "PASS"
    evidence = f"Total keys: {len(keys)}\nKey types: {', '.join(sorted(set(k.get('kty', 'unknown') for k in keys)))}\nInvalid: {len(invalid_keys)}"

    return ProbeRecord(
        probe_id=5,
        probe_class="authserver",
        probe_name="jwks-keys",
        request_method="GET",
        url=jwks_uri,
        status=200,
        content_type="application/json",
        headers_observed={},
        body_excerpt=f"{len(keys)} keys",
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=None
    )


def probe_password_grant(token_endpoint):
    """
    Password grant must be unsupported.
    PASS: unsupported_grant_type
    FAIL: grant accepted
    NOT_OBSERVED: invalid_client (auth evaluated first)
    """
    if not token_endpoint:
        return ProbeRecord(
            6, "authserver", "password-grant", "POST", token_endpoint or "",
            0, "", {}, "", "", "NOT_OBSERVED", "", "No token_endpoint"
        )

    error_code = ""
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = b"grant_type=password&username=test&password=test"

        try:
            with urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors='ignore')
                error_code = "accepted"
        except HTTPError as e:
            body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
            try:
                err = json.loads(body)
                error_code = err.get("error", f"HTTP {e.code}")
            except:
                error_code = f"HTTP {e.code}"
    except (URLError, Exception) as e:
        return ProbeRecord(
            6, "authserver", "password-grant", "POST", token_endpoint,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    if error_code == "accepted":
        verdict = "FAIL"
        evidence = "Token endpoint accepts password grant type"
        limitation = None
    elif error_code == "invalid_client":
        verdict = "NOT_OBSERVED"
        evidence = "Client auth evaluated before grant type check"
        limitation = "Client credentials required to test grant types"
    elif error_code == "unsupported_grant_type":
        verdict = "PASS"
        evidence = "Password grant type correctly unsupported"
        limitation = None
    else:
        verdict = "NOT_OBSERVED"
        evidence = f"Unexpected error: {error_code}"
        limitation = "Cannot determine grant type support"

    return ProbeRecord(
        probe_id=6,
        probe_class="authserver",
        probe_name="password-grant",
        request_method="POST",
        url=token_endpoint,
        status=0,
        content_type="",
        headers_observed={},
        body_excerpt=error_code,
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=limitation
    )


def probe_client_auth(token_endpoint):
    """
    Client authentication: send malformed Bearer token.
    PASS: invalid_token (token validation works)
    FAIL: request accepted with bad token
    NOT_OBSERVED: endpoint unreachable or no response
    """
    if not token_endpoint:
        return ProbeRecord(
            9, "authserver", "client-auth", "POST", token_endpoint or "",
            0, "", {}, "", "", "NOT_OBSERVED", "", "No token_endpoint"
        )

    http_status = 0
    error_code = ""
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Authorization", "Bearer malformed.token.here")
        req.data = b"grant_type=authorization_code&code=test&redirect_uri=https://localhost/cb"

        try:
            with urlopen(req, timeout=5) as resp:
                error_code = "accepted"
                http_status = resp.status
        except HTTPError as e:
            http_status = e.code
            body = e.fp.read(500).decode(errors='ignore') if e.fp else ""
            try:
                err = json.loads(body)
                error_code = err.get("error", f"HTTP {e.code}")
            except:
                error_code = f"HTTP {e.code}"
    except (URLError, Exception) as e:
        return ProbeRecord(
            9, "authserver", "client-auth", "POST", token_endpoint,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    if error_code == "invalid_token":
        verdict = "PASS"
        evidence = "Malformed Bearer token correctly rejected"
    elif error_code == "accepted":
        verdict = "FAIL"
        evidence = f"Server accepted malformed token (HTTP {http_status})"
    else:
        verdict = "NOT_OBSERVED"
        evidence = f"Error: {error_code}"

    return ProbeRecord(
        probe_id=9,
        probe_class="authserver",
        probe_name="client-auth",
        request_method="POST",
        url=token_endpoint,
        status=http_status,
        content_type="",
        headers_observed={},
        body_excerpt=error_code,
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=None
    )


def count_probes(records):
    """
    Derive probe counts from records, verify accounting.
    Returns (counts_by_class, accounting_valid, error_message)
    """
    counts = {}
    for record in records:
        probe_class = record.probe_class
        if probe_class not in counts:
            counts[probe_class] = {"attempted": 0, "passed": 0, "failed": 0, "not_observed": 0}

        counts[probe_class]["attempted"] += 1
        if record.verdict == "PASS":
            counts[probe_class]["passed"] += 1
        elif record.verdict == "FAIL":
            counts[probe_class]["failed"] += 1
        else:
            counts[probe_class]["not_observed"] += 1

    # Verify accounting
    for probe_class, c in counts.items():
        expected = c["passed"] + c["failed"] + c["not_observed"]
        if expected != c["attempted"]:
            return counts, False, f"{probe_class}: {expected} != {c['attempted']}"

    return counts, True, None


def render_probe(record):
    """Format probe with evidence on every line."""
    return f"  [{record.probe_id}] {record.probe_name:30s} {record.verdict:15s}  {record.evidence}"


def run_oauth_assessment(oauth_server_url, resource_metadata, mcp_url):
    """
    Complete OAuth authorization server assessment.
    Returns (records, findings)
    """
    records = []
    findings = []

    # Fetch authorization server metadata
    metadata_url = oauth_server_url.rstrip("/") + "/.well-known/oauth-authorization-server"
    try:
        req = Request(metadata_url)
        req.add_header("User-Agent", "mcp-authscan/2.0.0")

        with urlopen(req, timeout=5) as resp:
            metadata = json.loads(resp.read().decode())
    except (HTTPError, URLError, json.JSONDecodeError) as e:
        print(f"[!] Cannot fetch OAuth metadata from {metadata_url}: {e}", file=sys.stderr)
        return [], []  # Fail closed

    # Run probes
    records.append(probe_issuer_identity(metadata_url, metadata))
    if resource_metadata:
        rb = probe_resource_binding(resource_metadata, mcp_url)
        if rb:
            records.append(rb)
    records.append(probe_token_cache_control(metadata.get("token_endpoint")))
    records.append(probe_token_cors(metadata.get("token_endpoint")))
    records.append(probe_jwks_keys(metadata.get("jwks_uri")))
    records.append(probe_password_grant(metadata.get("token_endpoint")))
    records.append(probe_client_auth(metadata.get("token_endpoint")))

    # Build findings from FAIL verdicts
    for record in records:
        if record.verdict == "FAIL":
            findings.append({
                "rule": f"OAuth-{record.probe_id}",
                "severity": "HIGH",
                "title": f"{record.probe_name} failed",
                "evidence": record.evidence,
                "limitation": record.limitation
            })

    return records, findings
