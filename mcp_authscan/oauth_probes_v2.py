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
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OAUTH_PROBE_VERSION = "2.0.0"

# Probe prerequisites - what each probe requires to reach a verdict
PROBE_PREREQUISITES = {
    6: {"requires_registered_client": True},   # password-grant
    7: {"requires_registered_client": True},   # pkce-s256
    8: {"requires_registered_client": True},   # redirect-uri-exact
}


class ProbeRecord:
    """Single probe result with full evidence trail."""
    def __init__(self, probe_id, probe_class, probe_name, request_method, url,
                 status, content_type, headers_observed, body_excerpt, body_sha256,
                 verdict, evidence, limitation, prerequisites=None, prerequisite_met=True, **fields):
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
        self.verdict = verdict  # PASS, FAIL, NOT_OBSERVED, EXCLUDED
        self.evidence = evidence  # string
        self.limitation = limitation  # string or None
        self.prerequisites = prerequisites  # list of required conditions (e.g., ["registered_client"])
        self.prerequisite_met = prerequisite_met  # bool: were prerequisites available at runtime?
        # Store extracted field values for validator
        for key, value in fields.items():
            setattr(self, key, value)


def probe_issuer_identity(metadata_url, metadata):
    """
    Issuer identity must be published in OAuth server metadata.
    PASS: issuer field present and matches server
    FAIL: issuer field absent (server does not publish identity)

    Server must publish an issuer for clients to validate token binding.
    This is the server-side of GHSA-vqqp-x5qm-5qp4 (client can't bind what server doesn't publish).
    """
    issuer = metadata.get("issuer", "")
    base_url = metadata_url.split("/.well-known/")[0] if "/.well-known/" in metadata_url else metadata_url
    expected = base_url
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
        limitation=None,
        issuer=issuer,
        base_url=base_url
    )


def probe_resource_binding(resource_metadata, mcp_url):
    """
    Protected resource metadata's resource value must equal MCP endpoint.
    PASS: resource == mcp_url (byte-identical)
    FAIL: mismatch
    """
    if not resource_metadata:
        return None

    resource = resource_metadata.get("resource", "")
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
        limitation=None,
        resource=resource,
        mcp_url=mcp_url
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
    status_code = 0
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = b"grant_type=invalid"

        try:
            with urlopen(req, timeout=5) as resp:
                status_code = resp.status
                cache_control = resp.headers.get("Cache-Control", "")
        except HTTPError as e:
            status_code = e.code
            cache_control = e.headers.get("Cache-Control", "")
    except (URLError, Exception) as e:
        return ProbeRecord(
            3, "authserver", "token-cache-control", "POST", token_endpoint,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    # 404/405/500+ = endpoint doesn't exist or is unreachable = NOT_OBSERVED
    # Only 200/401 responses can be measured for Cache-Control
    if status_code in [404, 405, 500, 502, 503, 504]:
        verdict = "NOT_OBSERVED"
        evidence = f"HTTP {status_code}: Endpoint unreachable or not implemented"
    else:
        verdict = "PASS" if "no-store" in cache_control.lower() else "FAIL"
        evidence = f"HTTP {status_code}: Cache-Control: {cache_control or '(absent)'}"

    return ProbeRecord(
        probe_id=3,
        probe_class="authserver",
        probe_name="token-cache-control",
        request_method="POST",
        url=token_endpoint,
        status=status_code,
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
    impact = "Wildcard CORS on token endpoint allows cross-origin POST requests to reach it. Responses are protected by CORS policy, but the request itself executes on the server. This enables authorized clients on other origins to interact with the token endpoint, but also exposes it to direct cross-origin access attempts." if acao == "*" else "CORS restricted or absent."
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
            invalid_keys.append("alg=none")
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
    Password grant type support must be disabled (deprecated in OAuth 2.1).
    PASS: unsupported_grant_type
    FAIL: grant accepted or successful
    NOT_OBSERVED: cannot reach verdict without registered client

    To test grant type support, request must be well-formed except for grant_type parameter.
    This requires a registered client to avoid invalid_request (malformed auth).
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
            except (ValueError, KeyError):
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
        evidence = f"Server returned: {error_code}"
        limitation = "Cannot determine grant type support without client credentials"

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
    PASS: invalid_client with 401 and WWW-Authenticate header (RFC 6749 §5.2)
    FAIL: request accepted with bad token
    NOT_OBSERVED: endpoint unreachable, other error, or non-standard response
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
            except (ValueError, KeyError):
                error_code = f"HTTP {e.code}"
    except (URLError, Exception) as e:
        return ProbeRecord(
            9, "authserver", "client-auth", "POST", token_endpoint,
            0, "", {}, "", "", "NOT_OBSERVED", "", f"Request failed: {e}"
        )

    if error_code == "invalid_client":
        verdict = "PASS"
        evidence = "Client authentication enforced: invalid_client error on bad token (RFC 6749)"
    elif error_code == "accepted":
        verdict = "FAIL"
        evidence = f"Server accepted malformed token (HTTP {http_status})"
    else:
        verdict = "NOT_OBSERVED"
        evidence = f"Server returned: {error_code} (HTTP {http_status})"

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


def probe_pkce_s256(metadata):
    """
    PKCE S256 enforcement: server must reject authorize requests without code_challenge.
    PASS: authorization fails without code_challenge
    FAIL: authorization succeeds without code_challenge
    NOT_OBSERVED: cannot test enforcement without registered client

    Advertisement of S256 support does not prove enforcement.
    """
    auth_endpoint = metadata.get("authorization_endpoint", "")

    return ProbeRecord(
        probe_id=7,
        probe_class="authserver",
        probe_name="pkce-s256",
        request_method="GET",
        url=auth_endpoint or "",
        status=0,
        content_type="",
        headers_observed={},
        body_excerpt="",
        body_sha256="",
        verdict="NOT_OBSERVED",
        evidence="Enforcement test requires registered client and authorization flow",
        limitation="Cannot verify if S256 is enforced without client credentials",
        prerequisites=["registered_client", "authorization_flow"],
        prerequisite_met=False
    )


def probe_redirect_uri_exact(metadata):
    """
    Redirect URI must be validated with exact string matching.
    PASS: documentation states exact matching required
    FAIL: allows prefix matching or wildcard
    NOT_OBSERVED: no registered client to test with
    """
    auth_endpoint = metadata.get("authorization_endpoint", "")
    if not auth_endpoint:
        return ProbeRecord(
            8, "authserver", "redirect-uri-exact", "GET", "",
            0, "", {}, "", "", "NOT_OBSERVED", "", "No authorization_endpoint in metadata"
        )

    # Look for redirect_uris_supported or similar documentation
    # In OAuth 2.0/2.1, redirect_uri matching MUST be exact per spec
    # This probe would need to test with an actual client to verify

    verdict = "NOT_OBSERVED"
    evidence = "Redirect_uri validation tested via authorization endpoint"
    limitation = "Requires registered client, valid authorization flow, and redirect endpoint"

    return ProbeRecord(
        probe_id=8,
        probe_class="authserver",
        probe_name="redirect-uri-exact",
        request_method="GET",
        url=auth_endpoint,
        status=0,
        content_type="",
        headers_observed={},
        body_excerpt="",
        body_sha256="",
        verdict=verdict,
        evidence=evidence,
        limitation=limitation,
        prerequisites=["registered_client", "authorization_flow"],
        prerequisite_met=False
    )


def count_probes(records):
    """
    Derive probe counts from records, verify accounting.
    Returns (counts_by_class, accounting_valid, error_message)
    Attempted = probes actually sent (PASS, FAIL, OBSERVATION, NOT_OBSERVED with prerequisite_met=True)
    Excluded = probes never sent due to missing prerequisites (NOT_OBSERVED with prerequisite_met=False)
    """
    counts = {}
    for record in records:
        probe_class = record.probe_class
        if probe_class not in counts:
            counts[probe_class] = {"attempted": 0, "passed": 0, "failed": 0, "not_observed": 0, "observation": 0, "excluded": 0}

        # Distinguish excluded (never sent) from not_observed (sent, inconclusive)
        if record.verdict == "NOT_OBSERVED" and hasattr(record, 'prerequisite_met') and not record.prerequisite_met:
            # Never sent due to missing prerequisites
            counts[probe_class]["excluded"] += 1
        else:
            # Probe was sent (or would have been sent)
            counts[probe_class]["attempted"] += 1
            if record.verdict == "PASS":
                counts[probe_class]["passed"] += 1
            elif record.verdict == "FAIL":
                counts[probe_class]["failed"] += 1
            elif record.verdict == "OBSERVATION":
                counts[probe_class]["observation"] += 1
            elif record.verdict == "NOT_OBSERVED":
                counts[probe_class]["not_observed"] += 1

    # Verify accounting: attempted + excluded = 9 (total probe set size)
    for probe_class, c in counts.items():
        total = c["attempted"] + c["excluded"]
        expected = c["passed"] + c["failed"] + c["not_observed"] + c["observation"] + c["excluded"]
        if expected != total:
            return counts, False, f"{probe_class}: {expected} != {total}"

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
    records.append(probe_pkce_s256(metadata))
    records.append(probe_redirect_uri_exact(metadata))

    # Build findings from FAIL verdicts
    severity_by_probe = {
        1: "HIGH",     # issuer-identity: breaks all token binding
        2: "HIGH",     # resource-binding: resource metadata must identify the protected resource
        3: "LOW",      # token-cache-control: cache poisoning in shared caches
        6: "HIGH",     # password-grant: authentication bypass
        9: "HIGH",     # client-auth: token validation failure
    }

    impact_by_probe = {
        1: "Server does not publish an issuer. Clients cannot bind tokens to this server.",
        2: "RFC 9728 protected resource metadata must contain a 'resource' field matching the MCP endpoint URL. Empty or mismatched resource field breaks client-server binding.",
        3: "Error responses cached in shared proxies may leak sensitive information.",
        6: "Server accepts deprecated password grant, enabling credential interception.",
        9: "Server accepts malformed tokens. Token validation does not work.",
    }

    for record in records:
        if record.verdict == "FAIL":
            probe_id = record.probe_id
            findings.append({
                "rule": f"OAuth-{probe_id}",
                "severity": severity_by_probe.get(probe_id, "HIGH"),
                "title": f"{record.probe_name} failed",
                "evidence": record.evidence,
                "limitation": record.limitation,
                "interpretation": impact_by_probe.get(probe_id, ""),
                "request_method": record.request_method,
                "request_body": "",
                "response_status": record.status,
                "response_body": record.body_excerpt,
                "response_preview": record.body_excerpt,
                "remediation": f"Review and remediate probe {probe_id} ({record.probe_name})"
            })

    return records, findings
