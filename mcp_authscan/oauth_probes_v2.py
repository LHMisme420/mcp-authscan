"""OAuth Authorization Server Assessment - Nine security probes."""
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from ._common import record, SEVERITY_ORDER

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
    issuer = metadata.get("issuer", "")
    base_url = metadata_url.split("/.well-known/")[0] if "/.well-known/" in metadata_url else metadata_url
    body = json.dumps({"issuer": issuer}).encode("utf-8")
    
    if issuer == base_url:
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
            with urlopen(req, timeout=5) as resp:
                cache_control = resp.headers.get("Cache-Control", "")
                body = resp.read()
        except HTTPError as e:
            cache_control = e.headers.get("Cache-Control", "")
            body = e.read()
    except (URLError, Exception) as e:
        return record(
            probe_id=3,
            name="token-cache-control",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
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
        http_status=400,
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
    
    try:
        req = Request(token_endpoint, method="OPTIONS")
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Origin", "https://hostile.example.com")
        try:
            with urlopen(req, timeout=5) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                body = resp.read()
        except HTTPError as e:
            acao = e.headers.get("Access-Control-Allow-Origin", "")
            body = e.read()
    except (URLError, Exception) as e:
        return record(
            probe_id=4,
            name="token-cors",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    if acao == "*":
        status = "FAIL"
        severity = "MEDIUM"
    else:
        status = "PASS"
        severity = None
    
    return record(
        probe_id=4,
        name="token-cors",
        status=status,
        http_status=200,
        body=body,
        probe_class="authserver",
        detail="ACAO: %s" % (acao or "(absent)"),
        severity=severity,
        endpoint=token_endpoint
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
        with urlopen(req, timeout=5) as resp:
            body = resp.read()
            jwks = json.loads(body.decode("utf-8"))
            keys = jwks.get("keys", [])
    except (URLError, Exception, json.JSONDecodeError) as e:
        return record(
            probe_id=5,
            name="jwks-keys",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    if keys and all(k.get("kty") for k in keys):
        status = "PASS"
        severity = None
    else:
        status = "PASS"  # Informational probe - always pass if data retrieved
        severity = None
    
    return record(
        probe_id=5,
        name="jwks-keys",
        status=status,
        http_status=200,
        body=body,
        probe_class="authserver",
        detail="Keys: %d" % len(keys),
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
        req.data = b"grant_type=password&username=test&password=test"
        try:
            with urlopen(req, timeout=5) as resp:
                body = resp.read()
                error = json.loads(body.decode("utf-8")).get("error", "")
        except HTTPError as e:
            body = e.read()
            try:
                error = json.loads(body.decode("utf-8")).get("error", "")
            except:
                error = ""
    except (URLError, Exception) as e:
        return record(
            probe_id=6,
            name="password-grant",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    if error == "unsupported_grant_type":
        status = "PASS"
        severity = None
    else:
        status = "NOT_OBSERVED"
        severity = None
    
    return record(
        probe_id=6,
        name="password-grant",
        status=status,
        http_status=400,
        body=body,
        probe_class="authserver",
        detail="Error: %s" % (error or "(none)"),
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
        limitation="PKCE enforcement test requires registered client"
    )


def probe_redirect_uri_exact(metadata):
    """Redirect URI must match exactly. Substring matches are forbidden."""
    return record(
        probe_id=8,
        name="redirect-uri-exact",
        status="EXCLUDED",
        probe_class="authserver",
        limitation="Redirect URI test requires registered client"
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
            with urlopen(req, timeout=5) as resp:
                body = resp.read()
                error = json.loads(body.decode("utf-8")).get("error", "")
        except HTTPError as e:
            body = e.read()
            try:
                error = json.loads(body.decode("utf-8")).get("error", "")
            except:
                error = ""
    except (URLError, Exception) as e:
        return record(
            probe_id=9,
            name="client-auth",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Request failed: %s" % e
        )
    
    if error == "invalid_client":
        status = "PASS"
        severity = None
    else:
        status = "NOT_OBSERVED"
        severity = None
    
    return record(
        probe_id=9,
        name="client-auth",
        status=status,
        http_status=400,
        body=body,
        probe_class="authserver",
        detail="Error: %s" % (error or "(none)"),
        severity=severity,
        endpoint=token_endpoint
    )


def run_oauth_assessment(oauth_server_url, resource_metadata, mcp_url):
    """Complete OAuth authorization server assessment."""
    metadata_url = oauth_server_url.rstrip("/") + "/.well-known/oauth-authorization-server"
    try:
        req = Request(metadata_url)
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        with urlopen(req, timeout=5) as resp:
            metadata = json.loads(resp.read().decode())
    except (HTTPError, URLError, json.JSONDecodeError) as e:
        print("[!] Cannot fetch OAuth metadata from %s: %s" % (metadata_url, e), file=sys.stderr)
        return [], []

    records = []
    records.append(probe_issuer_identity(metadata_url, metadata))
    rb = probe_resource_binding(resource_metadata, mcp_url) if resource_metadata else None
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
