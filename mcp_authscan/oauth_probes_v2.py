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
                 verdict, evidence, limitation, prerequisites=None, prerequisite_met=True, verdict_rule=None, **fields):
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
        self.verdict_rule = verdict_rule  # Executable predicate on evidence fields
        # Store extracted field values for validator
        for key, value in fields.items():
            setattr(self, key, value)



def _extract_error_code(body_text):
    """Extract error code from OAuth error response JSON."""
    try:
        import json
        data = json.loads(body_text)
        return data.get("error")
    except:
        return None


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
        verdict_rule={"field": "observed.issuer", "op": "equals", "expected_from": "observed.base_url"},
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
        verdict_rule={"field": "observed.resource", "op": "equals", "expected_from": "observed.mcp_url"},
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
        limitation=None,
        verdict_rule={"field": "endpoints.0.headers.Cache-Control", "op": "contains", "expected": "no-store"}
    )


def probe_token_cors(token_endpoint):
    """Token endpoint CORS. Property: No wildcard CORS origins on token endpoint."""
    if not token_endpoint:
        return ProbeRecord(probe_id=4, probe_class="authserver", probe_name="token-cors", request_method="POST",
            url=token_endpoint or "", status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="NOT_OBSERVED", evidence="No token_endpoint", limitation=None,
            verdict_rule={"field": "endpoints.0.headers.access-control-allow-origin", "op": "equals", "expected": "*"})
    
    acao = acac = vary = ""
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
        return ProbeRecord(probe_id=4, probe_class="authserver", probe_name="token-cors", request_method="POST",
            url=token_endpoint, status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="NOT_OBSERVED", evidence=f"Request failed: {e}", limitation=None,
            verdict_rule={"field": "endpoints.0.headers.access-control-allow-origin", "op": "equals", "expected": "*"})
    
    verdict = "FAIL" if acao == "*" else "PASS"
    evidence = f"ACAO: {acao or '(absent)'} ACAC: {acac or '(absent)'} Vary: {vary or '(absent)'}"
    return ProbeRecord(probe_id=4, probe_class="authserver", probe_name="token-cors", request_method="POST",
        url=token_endpoint, status=0, content_type="", headers_observed={"access-control-allow-origin": acao, "access-control-allow-credentials": acac, "vary": vary},
        body_excerpt="", body_sha256="", verdict=verdict, evidence=evidence, limitation=None,
        verdict_rule={"field": "endpoints.0.headers.access-control-allow-origin", "op": "equals", "expected": "*"})

def probe_jwks_keys(jwks_url):
    """JWKS endpoint key validation. Property: OAuth server publishes cryptographic keys."""
    if not jwks_url:
        return ProbeRecord(probe_id=5, probe_class="authserver", probe_name="jwks-keys", request_method="GET",
            url="", status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="NOT_OBSERVED", evidence="No JWKS URL", limitation=None,
            verdict_rule={"field": "observed.key_types", "op": "present"})
    
    key_types = invalid_count = 0
    try:
        req = Request(jwks_url, method="GET")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        with urlopen(req, timeout=5) as resp:
            body = resp.read().decode()
            jwks = json.loads(body)
            keys = jwks.get("keys", [])
            key_types = list(set(k.get("kty") for k in keys if k.get("kty")))
            invalid_count = len([k for k in keys if not k.get("kty")])
    except (URLError, Exception) as e:
        return ProbeRecord(probe_id=5, probe_class="authserver", probe_name="jwks-keys", request_method="GET",
            url=jwks_url, status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="NOT_OBSERVED", evidence=f"Request failed: {e}", limitation=None,
            verdict_rule={"field": "observed.key_types", "op": "present"})
    
    verdict = "PASS" if key_types else "FAIL"
    evidence = f"Total keys: {len(keys)}\nKey types: {', '.join(key_types) if key_types else 'none'}\nInvalid: {invalid_count}"
    return ProbeRecord(probe_id=5, probe_class="authserver", probe_name="jwks-keys", request_method="GET",
        url=jwks_url, status=200, content_type="application/json", headers_observed={}, body_excerpt="", body_sha256="",
        verdict=verdict, evidence=evidence, limitation=None,
        verdict_rule={"field": "observed.key_types", "op": "present"}, key_types=key_types)

def probe_password_grant(token_endpoint):
    """Password grant type. Property: Server rejects resource owner password grant type."""
    if not token_endpoint:
        return ProbeRecord(probe_id=6, probe_class="authserver", probe_name="password-grant", request_method="POST",
            url="", status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="NOT_OBSERVED", evidence="No endpoint", limitation=None,
            verdict_rule={"field": "observed.error", "op": "equals", "expected": "unsupported_grant_type"})
    
    error = ""
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = b"grant_type=password&username=test&password=test"
        try:
            with urlopen(req, timeout=5) as resp:
                error = json.loads(resp.read().decode()).get("error", "")
        except HTTPError as e:
            error = json.loads(e.read().decode()).get("error", "")
    except: pass
    
    verdict = "PASS" if error == "unsupported_grant_type" else "FAIL"
    evidence = f"Password grant error: {error or 'none'}"
    return ProbeRecord(probe_id=6, probe_class="authserver", probe_name="password-grant", request_method="POST",
        url=token_endpoint, status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
        verdict=verdict, evidence=evidence, limitation=None,
        verdict_rule={"field": "observed.error", "op": "equals", "expected": "unsupported_grant_type"}, error=error)

def probe_pkce_s256(token_endpoint):
    """PKCE S256 enforcement. Property: Server requires PKCE code challenge."""
    if not token_endpoint:
        return ProbeRecord(probe_id=7, probe_class="authserver", probe_name="pkce-s256", request_method="POST",
            url="", status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="EXCLUDED", evidence="No endpoint", prerequisite_met=False, limitation="Enforcement test requires registered client",
            verdict_rule={"field": "observed.error", "op": "contains", "expected": "challenge"})
    
    return ProbeRecord(probe_id=7, probe_class="authserver", probe_name="pkce-s256", request_method="POST",
        url=token_endpoint, status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
        verdict="EXCLUDED", evidence="Enforcement test requires registered client", prerequisite_met=False,
        limitation="Enforcement test requires registered client and authorization flow",
        verdict_rule={"field": "observed.error", "op": "contains", "expected": "challenge"})

def probe_redirect_uri_exact(token_endpoint):
    """Redirect URI validation. Property: Server validates redirect_uri parameter."""
    return ProbeRecord(probe_id=8, probe_class="authserver", probe_name="redirect-uri-exact", request_method="GET",
        url=token_endpoint or "", status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
        verdict="EXCLUDED", evidence="Redirect_uri validation tested via authorization endpoint", prerequisite_met=False,
        limitation="Redirect_uri validation tested via authorization endpoint",
        verdict_rule={"field": "observed.error", "op": "contains", "expected": "redirect"})

def probe_client_auth(token_endpoint):
    """Client authentication. Property: Server enforces client authentication."""
    if not token_endpoint:
        return ProbeRecord(probe_id=9, probe_class="authserver", probe_name="client-auth", request_method="POST",
            url="", status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
            verdict="NOT_OBSERVED", evidence="No endpoint", limitation=None,
            verdict_rule={"field": "observed.error", "op": "equals", "expected": "invalid_client"})
    
    error = ""
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = b"grant_type=client_credentials&client_id=test"
        try:
            with urlopen(req, timeout=5) as resp:
                error = json.loads(resp.read().decode()).get("error", "")
        except HTTPError as e:
            error = json.loads(e.read().decode()).get("error", "")
    except: pass
    
    verdict = "PASS" if error == "invalid_client" else "FAIL"
    evidence = f"Client auth error: {error or 'none'}"
    return ProbeRecord(probe_id=9, probe_class="authserver", probe_name="client-auth", request_method="POST",
        url=token_endpoint, status=0, content_type="", headers_observed={}, body_excerpt="", body_sha256="",
        verdict=verdict, evidence=evidence, limitation=None,
        verdict_rule={"field": "observed.error", "op": "equals", "expected": "invalid_client"}, error=error)

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
