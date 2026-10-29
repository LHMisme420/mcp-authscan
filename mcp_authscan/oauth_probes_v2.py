"""OAuth Authorization Server Assessment - Nine security probes."""
import json
import os
import sys
from urllib.error import HTTPError, URLError
from .errors import EgressRefusalError
from urllib.request import Request, urlopen
from ._common import record, SEVERITY_ORDER
from urllib.parse import urlparse, urlencode
import socket
from .monolith import assert_url_is_fetchable

def _egress_guard(request_obj, timeout=5, allow_private=None, allowed_hosts=None):
    """Egress guard: enforce scope on all outbound requests.
    
    Checks that request_obj.full_url is fetchable (globally routable, not SSRF)
    and that the hostname is in the authorized set.
    Raises EgressRefusalError if the target is outside scope.
    Returns (status_code, headers_dict, body_bytes) on success.
    """
    try:
        assert_url_is_fetchable(request_obj.full_url, allow_private=allow_private)
    except ValueError as e:
        raise EgressRefusalError(str(e))
    
    # Check hostname against authorized set
    from mcp_authscan.monolith import ALLOWED_HOSTS
    from urllib.parse import urlparse
    parsed = urlparse(request_obj.full_url)
    hostname = (parsed.hostname or '').lower()
    if hostname and hostname not in ALLOWED_HOSTS:
        raise EgressRefusalError(f"host {hostname} not in authorized set: {sorted(ALLOWED_HOSTS)}")
    
    try:
        with urlopen(request_obj, timeout=timeout) as resp:
            return (resp.status, dict(resp.headers), resp.read())
    except HTTPError as e:
        return (e.code, dict(e.headers), e.read())


def _client_creds(client_id=None, client_secret=None, redirect_uri=None):
    """Resolve OAuth client credentials: explicit argument, else environment."""
    return (
        client_id or os.environ.get("MCPAUTHSCAN_CLIENT_ID"),
        client_secret or os.environ.get("MCPAUTHSCAN_CLIENT_SECRET"),
        redirect_uri or os.environ.get("MCPAUTHSCAN_REDIRECT_URI"),
    )


OAUTH_PROBE_VERSION = "2.0.0"


class ProbeRecord:
    """Single probe result with full evidence trail."""
    def __init__(self, probe_id, name, status, *, http_status=None,
                 headers_observed=None, body_excerpt="", body_sha256=None,
                 prerequisites=None, prerequisite_met=True, limitation=None,
                 probe_class=None, detail=None, severity=None, endpoint=None):
        self.probe_id = probe_id
        self.name = name
        self.status = status
        self.http_status = http_status
        self.headers_observed = headers_observed or {}
        self.body_excerpt = body_excerpt
        self.body_sha256 = body_sha256
        self.prerequisites = list(prerequisites or [])
        self.prerequisite_met = prerequisite_met
        self.limitation = limitation
        self.probe_class = probe_class
        self.detail = detail
        self.severity = severity
        self.endpoint = endpoint

    def as_dict(self):
        return {
            "probe_id": self.probe_id,
            "name": self.name,
            "status": self.status,
            "http_status": self.http_status,
            "headers_observed": dict(self.headers_observed or {}),
            "body_excerpt": self.body_excerpt,
            "body_sha256": self.body_sha256,
            "prerequisites": list(self.prerequisites or []),
            "prerequisite_met": self.prerequisite_met,
            "limitation": self.limitation,
            "probe_class": self.probe_class,
            "detail": self.detail,
            "severity": self.severity,
            "endpoint": self.endpoint,
        }


def probe_issuer_identity(metadata_url, metadata):
    """Issuer identity must be published in OAuth server metadata."""
    base_url = metadata_url.split("/.well-known/")[0] if "/.well-known/" in metadata_url else metadata_url
    
    # Explicit presence check: issuer field is required
    issuer = metadata.get("issuer")
    if issuer is None:
        body = json.dumps({"issuer": None}).encode("utf-8")
        return record(
            probe_id=1,
            name="issuer-identity",
            status="FAIL",
            http_status=200,
            body=body,
            probe_class="authserver",
            detail="issuer field is missing from OAuth metadata (required)",
            severity="HIGH",
            endpoint=metadata_url
        )
    
    # Issuer present: check if it matches expected value (normalize trailing slashes)
    body = json.dumps({"issuer": issuer}).encode("utf-8")
    issuer_norm = issuer.rstrip('/')
    base_url_norm = base_url.rstrip('/')
    if issuer_norm == base_url_norm:
        status = "PASS"
        severity = None
    else:
        status = "FAIL"
        severity = "HIGH"
    
    return record(
        probe_id=1,
        name="issuer-identity",
        status=status,
        http_status=200,
        body=body,
        probe_class="authserver",
        detail="issuer=%s base_url=%s" % (issuer, base_url),
        severity=severity,
        endpoint=metadata_url
    )


def probe_resource_binding(resource_metadata, mcp_url):
    """Protected resource metadata's resource value must equal MCP endpoint."""
    if not resource_metadata:
        return record(
            probe_id=2,
            name="resource-binding",
            status="EXCLUDED",
            probe_class="authserver",
            limitation="No resource metadata"
        )
    
    resource = resource_metadata.get("resource", "")
    body = json.dumps({"resource": resource}).encode("utf-8")
    
    if resource == mcp_url:
        status = "PASS"
        severity = None
    else:
        status = "FAIL"
        severity = "HIGH"
    
    return record(
        probe_id=2,
        name="resource-binding",
        status=status,
        http_status=200,
        body=body,
        probe_class="authserver",
        detail="resource=%s mcp_url=%s" % (resource, mcp_url),
        severity=severity,
        endpoint=mcp_url
    )


def probe_token_cache_control(token_endpoint):
    """Token endpoint error responses must carry Cache-Control: no-store."""
    if not token_endpoint:
        return record(
            probe_id=3,
            name="token-cache-control",
            status="EXCLUDED",
            probe_class="authserver",
            limitation="No token endpoint"
        )
    
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.data = b"grant_type=invalid"
        try:
            http_status, headers, body = _egress_guard(req)
        except EgressRefusalError:
            return record(
                probe_id=3,
                name="token-cache-control",
                status="EXCLUDED",
                probe_class="authserver",
                limitation="Target URL outside allowed scope"
            )
    except Exception as e:
        return record(
            probe_id=3,
            name="token-cache-control",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    # Read Cache-Control from the /token response
    cache_control = headers.get("Cache-Control", "").lower()
    import sys
    print(f"[DEBUG] token-cache-control: status={http_status}, cache_control={repr(cache_control)}", file=sys.stderr)
    
    if http_status and http_status >= 500:
        return record(
            probe_id=3,
            name="token-cache-control",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Token endpoint returned %d (server error). Cache headers cannot be evaluated." % http_status,
            endpoint=token_endpoint
        )
    
    if "no-store" in cache_control:
        status = "PASS"
        severity = None
    else:
        status = "FAIL"
        severity = "LOW"
    
    return record(
        probe_id=3,
        name="token-cache-control",
        status=status,
        http_status=http_status or 400,
        body=body,
        probe_class="authserver",
        detail="Cache-Control: %s" % (cache_control or "(absent)"),
        severity=severity,
        endpoint=token_endpoint
    )


def probe_token_cors(token_endpoint):
    """Token endpoint must not expose credentials to cross-origin requests."""
    if not token_endpoint:
        return record(
            probe_id=4,
            name="token-cors",
            status="EXCLUDED",
            probe_class="authserver",
            limitation="No token endpoint"
        )

    headers = {}
    http_status = None
    body = b""
    acao = ""
    origin_sent = "https://hostile.example.com"

    try:
        # Check CORS on POST (the request that carries credentials)
        # Probe: POST with hostile Origin header
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Origin", origin_sent)
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        cid, csec, _ = _client_creds()
        sent_credentials = bool(cid)
        if cid:
            form = {"grant_type": "client_credentials", "client_id": cid}
            if csec:
                form["client_secret"] = csec
            req.data = urlencode(form).encode()
        else:
            req.data = b"grant_type=invalid"
        try:
            http_status, headers, body = _egress_guard(req)
            # Case-insensitive ACAO lookup: HTTP headers are case-insensitive per RFC 7230
            acao = next((v for k, v in headers.items() if k.lower() == "access-control-allow-origin"), "")
        except EgressRefusalError:
            return record(
                probe_id=4,
                name="token-cors",
                status="NOT_OBSERVED",
                probe_class="authserver",
                detail="Target URL outside allowed scope"
            )
    except (URLError, Exception) as e:
        return record(
            probe_id=4,
            name="token-cors",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    # Check for error responses before evaluating verdict.
    # 4xx with valid OAuth error structure is OK; exclude only on non-JSON or missing error code.
    try:
        body_json = json.loads(body) if body else {}
        has_error_code = isinstance(body_json, dict) and "error" in body_json
    except (ValueError, TypeError):
        has_error_code = False
    
    if http_status and 400 <= http_status < 500 and not has_error_code:
        return record(
            probe_id=4,
            name="token-cors",
            status="EXCLUDED",
            http_status=http_status,
            probe_class="authserver",
            detail="Endpoint returned error; cannot assess CORS configuration"
        )
    # 5xx: server error; cannot assess. Return NOT_OBSERVED.
    if http_status and http_status >= 500:
        status = "NOT_OBSERVED"
        severity = None
        title = None
        remediation = None
    elif not (http_status and 200 <= http_status < 300):
        # Only a 2xx can convict or acquit the CORS property; an error response proves nothing.
        status = "NOT_OBSERVED"
        severity = None
        title = None
        remediation = None
    elif acao == "":
        # 2xx with no ACAO: token response is not exposed cross-origin.
        status = "PASS"
        severity = None
        title = None
        remediation = None
    elif acao == "*" or acao == origin_sent:
        # Wildcard or echo on a 2xx token response: CORS misconfiguration
        status = "FAIL"
        severity = "CRITICAL" if sent_credentials else "HIGH"
        title = "CORS misconfiguration on OAuth token endpoint"
        remediation = "Restrict Access-Control-Allow-Origin on the token endpoint to the specific origins that need it (not * or request origin)"
    else:
        status = "PASS"
        severity = None
        title = None
        remediation = None
    
    # Construct detail based on response status and ACAO value
    if status == "FAIL":
        if http_status == 400:
            detail = f"ACAO: {acao} (on 400 error response: cross-origin requester receives error, not token)"
        else:
            detail = f"ACAO: {acao}"
    else:
        detail = "ACAO: %s" % (acao or "(absent)")
    
    return record(
        probe_id=4,
        name="token-cors",
        status=status,
        http_status=http_status,
        headers=headers,
        body=body,
        evidence="headers",
        probe_class="authserver",
        detail=detail,
        severity=severity,
        endpoint=token_endpoint,
        prerequisites=[] if status == "PASS" else ["token_endpoint"],
        prerequisite_met=True if token_endpoint else False,
    )


def probe_jwks_keys(jwks_uri):
    """JWKS endpoint must publish valid cryptographic keys."""
    if not jwks_uri:
        return record(
            probe_id=5,
            name="jwks-keys",
            status="EXCLUDED",
            probe_class="authserver",
            limitation="No JWKS endpoint"
        )
    
    try:
        req = Request(jwks_uri)
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        status_code, headers, body = _egress_guard(req, allow_private=ALLOW_PRIVATE_TARGETS)
        jwks = json.loads(body.decode("utf-8"))
        keys = jwks.get("keys", [])
    except EgressRefusalError:
        return record(
            probe_id=5,
            name="jwks-keys",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Target URL outside allowed scope"
        )
    except (URLError, Exception, json.JSONDecodeError) as e:
        return record(
            probe_id=5,
            name="jwks-keys",
            status="EXCLUDED",
            probe_class="authserver",
            detail="Cannot reach JWKS endpoint"
        )
    
    # Explicit check: keys must be asymmetric (RSA, EC, etc)
    # Symmetric keys (oct) in signing context are a failure
    asymmetric_ktys = {"RSA", "EC", "EdDSA", "OKP"}  # Asymmetric key types
    
    if not keys:
        # No keys published
        status = "FAIL"
        severity = "HIGH"
        detail = "No keys published in JWKS"
    else:
        # Check if all keys are asymmetric
        asymmetric_keys = [k for k in keys if k.get("kty") in asymmetric_ktys]
        if not asymmetric_keys:
            # All keys are symmetric or unknown - that's a failure for signing
            status = "FAIL"
            severity = "HIGH"
            detail = "Keys: %d (all symmetric or unknown - signing keys must be asymmetric)" % len(keys)
        else:
            status = "PASS"
            severity = None
            detail = "Keys: %d asymmetric" % len(asymmetric_keys)
    
    return record(
        probe_id=5,
        name="jwks-keys",
        status=status,
        http_status=200,
        body=body,
        probe_class="authserver",
        detail=detail,
        severity=severity,
        endpoint=jwks_uri
    )


def probe_password_grant(token_endpoint):
    """Password grant is deprecated. Server must not accept it."""
    if not token_endpoint:
        return record(
            probe_id=6,
            name="password-grant",
            status="EXCLUDED",
            probe_class="authserver",
            limitation="No token endpoint"
        )
    
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        cid, csec, _ = _client_creds()
        form = {"grant_type": "password", "username": "test", "password": "test"}
        if cid:
            form["client_id"] = cid
        if csec:
            form["client_secret"] = csec
        req.data = urlencode(form).encode()
        http_status, headers, body = _egress_guard(req)
        try:
            response = json.loads(body.decode("utf-8"))
            error = response.get("error", "")
        except (json.JSONDecodeError, UnicodeDecodeError):
            response = {}
            error = ""
    except (URLError, Exception) as e:
        return record(
            probe_id=6,
            name="password-grant",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    token = response.get("access_token")
    if 200 <= http_status < 300 and isinstance(token, str) and token.strip() and not error:
        status = "FAIL"
        severity = "HIGH"
    elif 400 <= http_status < 500 and error == "unsupported_grant_type":
        status = "PASS"
        severity = None
    else:
        status = "NOT_OBSERVED"
        severity = None
    
    return record(
        probe_id=6,
        name="password-grant",
        status=status,
        http_status=http_status,
        body=body,
        probe_class="authserver",
        detail=("Token issued using the deprecated password grant" if status == "FAIL"
                else "Error: %s" % (error or "(none)")),
        severity=severity,
        endpoint=token_endpoint
    )


def probe_pkce_s256(metadata):
    """PKCE S256 must be required for authorization requests."""
    return record(
        probe_id=7,
        name="pkce-s256",
        status="EXCLUDED",
        probe_class="authserver",
        limitation="PKCE enforcement test requires registered client",
        prerequisites=["registered_client"],
        prerequisite_met=False,
    )


def probe_redirect_uri_exact(metadata):
    """Redirect URI must match exactly. Substring matches are forbidden."""
    return record(
        probe_id=8,
        name="redirect-uri-exact",
        status="EXCLUDED",
        probe_class="authserver",
        limitation="Redirect URI test requires registered client",
        prerequisites=["registered_client"],
        prerequisite_met=False,
    )


def probe_client_auth(token_endpoint):
    """Client authentication must be enforced on token endpoint."""
    if not token_endpoint:
        return record(
            probe_id=9,
            name="client-auth",
            status="EXCLUDED",
            probe_class="authserver",
            limitation="No token endpoint"
        )
    
    try:
        req = Request(token_endpoint, method="POST")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.data = b"grant_type=authorization_code&code=invalid"
        try:
            http_status, headers, body = _egress_guard(req)
            response = json.loads(body.decode("utf-8"))
            error = response.get("error", "")
        except json.JSONDecodeError:
            http_status = 400
            response = {}
            error = ""
    except (URLError, Exception) as e:
        return record(
            probe_id=9,
            name="client-auth",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    token = response.get("access_token")
    if 200 <= http_status < 300 and isinstance(token, str) and token.strip() and not error:
        status = "FAIL"
        severity = "HIGH"
    elif 400 <= http_status < 500 and error == "invalid_client":
        status = "PASS"
        severity = None
    else:
        status = "NOT_OBSERVED"
        severity = None
    
    return record(
        probe_id=9,
        name="client-auth",
        status=status,
        http_status=http_status,
        body=body,
        probe_class="authserver",
        detail=("Token issued for an invalid code without client authentication" if status == "FAIL"
                else "Error: %s" % (error or "(none)")),
        severity=severity,
        endpoint=token_endpoint
    )


def run_oauth_assessment(oauth_server_url, resource_metadata, mcp_url, allowed_hosts=None, allow_private=False):
    """Complete OAuth authorization server assessment."""
    metadata_url = oauth_server_url.rstrip("/") + "/.well-known/oauth-authorization-server"
    try:
        req = Request(metadata_url)
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        status_code, headers, body = _egress_guard(req, allow_private=ALLOW_PRIVATE_TARGETS)
        metadata = json.loads(body.decode())
    except EgressRefusalError as e:
        print("[!] OAuth server outside allowed scope: %s" % e, file=sys.stderr)
        return [], []
    except (URLError, json.JSONDecodeError) as e:
        print("[!] Cannot fetch OAuth metadata from %s: %s" % (metadata_url, e), file=sys.stderr)
        return [], []

    records = []
    records.append(probe_issuer_identity(metadata_url, metadata))
    rb = probe_resource_binding(resource_metadata, mcp_url)
    if rb:
        records.append(rb)
    records.append(probe_token_cache_control(metadata.get("token_endpoint")))
    records.append(probe_token_cors(metadata.get("token_endpoint")))
    records.append(probe_jwks_keys(metadata.get("jwks_uri")))
    records.append(probe_password_grant(metadata.get("token_endpoint")))
    records.append(probe_pkce_s256(metadata))
    records.append(probe_redirect_uri_exact(metadata))
    records.append(probe_client_auth(metadata.get("token_endpoint")))
    
    return records, []


def count_probes(records):
    """Count probe results."""
    from .counts import count_probes as _count
    return _count(records)


def render_probe(record):
    """Format probe for stderr display."""
    return "[%d] %-20s %s" % (record.probe_id, record.name, record.status)
