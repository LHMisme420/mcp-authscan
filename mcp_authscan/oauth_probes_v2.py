"""OAuth Authorization Server Assessment - Nine security probes."""
import json
import os
import sys
from urllib.error import HTTPError, URLError
from .errors import EgressRefusalError
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from ._common import record, redact_secrets, SEVERITY_ORDER
from urllib.parse import urlparse, urlencode, urlsplit, urlunsplit, urljoin, parse_qsl
import base64
import hashlib
import secrets
import socket
from .monolith import assert_url_is_fetchable

from mcp_authscan.http_headers import Headers


class _NoRedirect(HTTPRedirectHandler):
    """Never follow a redirect: the 3xx comes back as an HTTPError carrying its Location."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirect)


def _egress_guard(request_obj, timeout=5, allow_private=None, allowed_hosts=None, follow_redirects=True):
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
    
    opener = urlopen if follow_redirects else _NO_REDIRECT_OPENER.open
    try:
        with opener(request_obj, timeout=timeout) as resp:
            return (resp.status, Headers(resp.headers), resp.read())
    except HTTPError as e:
        return (e.code, Headers(e.headers), e.read())


def _client_creds(client_id=None, client_secret=None, redirect_uri=None):
    """Resolve OAuth client credentials: explicit argument, else environment."""
    return (
        client_id or os.environ.get("MCPAUTHSCAN_CLIENT_ID"),
        client_secret or os.environ.get("MCPAUTHSCAN_CLIENT_SECRET"),
        redirect_uri or os.environ.get("MCPAUTHSCAN_REDIRECT_URI"),
    )


OAUTH_PROBE_VERSION = "2.0.0"

# Redirect URI for a dynamically registered client (RFC 7591), chosen and controlled by the
# scanner: a loopback address (RFC 8252) where nothing listens. Probes never follow a redirect
# and never fetch a Location, so nothing is ever sent to it.
SCANNER_REDIRECT_URI = "http://127.0.0.1/mcp-authscan/callback"

# token-cors [4] acquired-token mode (--acquire-token). Off by default: the probe then sends one
# POST with no authorization code. When True it obtains a real access token through one
# authorization-code request with PKCE S256 and takes its verdict from the token response.
ACQUIRE_TOKEN = False

HOSTILE_ORIGIN = "https://hostile.example.com"
CONSENT_LIMITATION = "Consent requires human interaction, cannot complete unattended"

# One entry per run_oauth_assessment: where probes 7 and 8 got their client, the redirect used,
# and what the revocation returned. Holds no secret. scan_live_server clears it per scan.
CLIENT_REPORTS = []


class _Client:
    """A client for authorization requests. secret and registration_access_token stay in memory
    only; repr never shows them."""
    __slots__ = ("client_id", "redirect_uri", "source", "usable", "secret", "registration_access_token")

    def __init__(self, client_id, redirect_uri, source, usable=True, secret=None, registration_access_token=None):
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.source = source
        self.usable = usable
        self.secret = secret
        self.registration_access_token = registration_access_token

    def __repr__(self):
        return "<client %s source=%s>" % (self.client_id, self.source)


def _oauth_error(body):
    """The "error" string of a JSON error body, else None."""
    try:
        doc = json.loads((body or b"").decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    err = doc.get("error") if isinstance(doc, dict) else None
    return err if isinstance(err, str) and err else None


def _status_text(status, body):
    err = _oauth_error(body)
    return "HTTP %d%s" % (status, (" error=%s" % err) if err else "")


def _register_client(metadata):
    """RFC 7591 registration at the advertised registration_endpoint, redirect SCANNER_REDIRECT_URI.

    Returns (client, reason). client is None when no client was created; a client whose response
    did not list SCANNER_REDIRECT_URI is returned with usable=False so it is still revoked.
    Exceptions are reported by type only, never by message.
    """
    if not metadata.get("authorization_endpoint"):
        return None, "not attempted: no authorization_endpoint advertised"
    endpoint = metadata.get("registration_endpoint")
    if not endpoint:
        return None, "no registration_endpoint advertised"
    req = Request(endpoint, method="POST", data=json.dumps({
        "client_name": "mcp-authscan",
        "redirect_uris": [SCANNER_REDIRECT_URI],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }).encode("utf-8"))
    req.add_header("User-Agent", "mcp-authscan/2.0.0")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    try:
        status, _, body = _egress_guard(req, follow_redirects=False)
    except EgressRefusalError:
        return None, "registration_endpoint outside allowed scope"
    except Exception as e:
        return None, "registration request failed: %s" % type(e).__name__
    if not 200 <= status < 300:
        return None, "registration returned " + _status_text(status, body)
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        doc = None
    client_id = doc.get("client_id") if isinstance(doc, dict) else None
    if not isinstance(client_id, str) or not client_id.strip():
        return None, "registration response carried no client_id"
    client = _Client(client_id, SCANNER_REDIRECT_URI, "registered",
                     secret=doc.get("client_secret"),
                     registration_access_token=doc.get("registration_access_token"))
    uris = doc.get("redirect_uris")
    if uris is not None and not (isinstance(uris, list) and SCANNER_REDIRECT_URI in uris):
        client.usable = False
        return client, "registration response did not list the scanner's redirect_uri %s" % SCANNER_REDIRECT_URI
    return client, "HTTP %d, client_id %s" % (status, client_id)


def _revoke_client(metadata, client):
    """One form POST to the advertised revocation_endpoint for a registered client.

    Sends client_id, plus token=registration_access_token when the registration returned one.
    Returns what came back; the client's credentials are dropped either way.
    """
    endpoint = metadata.get("revocation_endpoint")
    form = {"client_id": client.client_id}
    if client.registration_access_token:
        form["token"] = client.registration_access_token
    client.secret = client.registration_access_token = None
    if not endpoint:
        return "not attempted: no revocation_endpoint advertised"
    req = Request(endpoint, method="POST", data=urlencode(form).encode("ascii"))
    form = None
    req.add_header("User-Agent", "mcp-authscan/2.0.0")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        status, _, body = _egress_guard(req, follow_redirects=False)
    except EgressRefusalError:
        return "revocation_endpoint outside allowed scope"
    except Exception as e:
        return "request failed: %s" % type(e).__name__
    return _status_text(status, body)


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


def _pkce_pair():
    """(verifier, S256 challenge) for a flow that redeems its code; the verifier stays in memory."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _header(headers, name):
    return next((v for k, v in (headers or {}).items() if k.lower() == name), "")


def _revoke_tokens(metadata, client, tokens):
    """RFC 7009 revocation of each (hint, token) at the advertised revocation_endpoint.

    Returns a summary; never the token. The caller drops its references afterwards.
    """
    endpoint = (metadata or {}).get("revocation_endpoint")
    if not endpoint:
        return "not attempted: no revocation_endpoint advertised"
    results = []
    for hint, token in tokens:
        form = {"token": token, "token_type_hint": hint, "client_id": client.client_id}
        if client.secret:
            form["client_secret"] = client.secret
        req = Request(endpoint, method="POST", data=urlencode(form).encode("ascii"))
        form = token = None
        req.add_header("User-Agent", "mcp-authscan/2.0.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            status, _, body = _egress_guard(req, follow_redirects=False)
            outcome = _status_text(status, body)
        except EgressRefusalError:
            outcome = "revocation_endpoint outside allowed scope"
        except Exception as e:
            outcome = "request failed: %s" % type(e).__name__
        req = None
        results.append("%s %s" % (hint, outcome))
    return "; ".join(results)


def _env_client():
    cid, secret, redirect = _client_creds()
    if cid and redirect:
        return _Client(cid, redirect, "environment (MCPAUTHSCAN_CLIENT_ID)", secret=secret)
    return None


def _token_cors_acquired(token_endpoint, metadata, client, registration_note):
    """token-cors [4] with --acquire-token: authorization code + PKCE S256, then the token
    exchange carries a hostile Origin and the verdict comes from that response.

    One authorization request; a consent page or a refusal ends the probe (no retry, no form
    submission). Redirects are never followed and the Location is never fetched. The code,
    verifier and tokens stay in local variables, are revoked before returning, and never
    reach the record: its body is redacted and failures are reported by exception type.
    """
    def result(status, detail, limitation=None, http_status=None, headers=None, body=b"", severity=None,
               prerequisite_met=True):
        return record(probe_id=4, name="token-cors", status=status, http_status=http_status,
                      headers=headers, body=body, evidence="headers", probe_class="authserver",
                      detail=detail, limitation=limitation, severity=severity,
                      endpoint=token_endpoint if status == "FAIL" else None,
                      prerequisites=["token_endpoint", "authorization_endpoint", "client"],
                      prerequisite_met=prerequisite_met)

    authorization_endpoint = (metadata or {}).get("authorization_endpoint")
    if not authorization_endpoint:
        return result("EXCLUDED", "Acquired-token mode (--acquire-token)",
                      limitation="No authorization endpoint", prerequisite_met=False)
    client = client or _env_client()
    if client is None:
        return result("EXCLUDED", registration_note or "Acquired-token mode (--acquire-token)",
                      limitation=("No client to obtain a token (registration supplied none and "
                                  "MCPAUTHSCAN_CLIENT_ID/MCPAUTHSCAN_REDIRECT_URI are not both set)"),
                      prerequisite_met=False)

    mode = "Acquired-token mode (--acquire-token), client %s (%s): " % (client.client_id, client.source)
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    try:
        response = _authorize(authorization_endpoint, {
            "response_type": "code", "client_id": client.client_id, "redirect_uri": client.redirect_uri,
            "state": state, "code_challenge": challenge, "code_challenge_method": "S256"})
    except EgressRefusalError:
        return result("NOT_OBSERVED", mode + "authorization_endpoint outside allowed scope")
    except Exception as e:
        return result("NOT_OBSERVED", mode + "authorization request failed: %s" % type(e).__name__)

    status, headers, _ = response
    location = headers.get("Location") if headers is not None else None
    absolute = urljoin(authorization_endpoint, location) if location else None
    params = {}
    if absolute:
        parts = urlsplit(absolute)
        params = dict(parse_qsl(parts.query)) | dict(parse_qsl(parts.fragment))
    recorded = {"Location": _redact_location(absolute)} if absolute else {}
    if absolute and 300 <= status < 400 and "error" in params:
        return result("NOT_OBSERVED", mode + "authorization refused: error=%s; no token obtained" % params["error"],
                      http_status=status, headers=recorded)
    if 400 <= status < 500 and _oauth_error(response[2]):
        return result("NOT_OBSERVED", mode + "authorization refused: error=%s; no token obtained"
                      % _oauth_error(response[2]), http_status=status)
    to_redirect = bool(absolute) and 300 <= status < 400 and _same_uri(absolute, client.redirect_uri)
    if status == 200 or (absolute and 300 <= status < 400 and not to_redirect
                         and _origin(absolute) == _origin(authorization_endpoint)):
        return result("NOT_OBSERVED", mode + CONSENT_LIMITATION + ": the authorization endpoint answered "
                      "HTTP %d with a consent step; the scanner sent one request and did not submit consent "
                      "or retry; no token obtained" % status, limitation=CONSENT_LIMITATION, http_status=status, headers=recorded)
    code = params.get("code") if to_redirect else None
    if not code or params.get("state") != state:
        why = "no code" if not code else "state mismatch"
        return result("NOT_OBSERVED", mode + "authorization response gave no usable code (HTTP %d, %s); no token obtained"
                      % (status, why), http_status=status, headers=recorded)

    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": client.redirect_uri,
            "client_id": client.client_id, "code_verifier": verifier}
    if client.secret:
        form["client_secret"] = client.secret
    req = Request(token_endpoint, method="POST", data=urlencode(form).encode("ascii"))
    form = code = verifier = None
    req.add_header("User-Agent", "mcp-authscan/2.0.0")
    req.add_header("Origin", HOSTILE_ORIGIN)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    try:
        http_status, headers, body = _egress_guard(req, follow_redirects=False)
    except EgressRefusalError:
        return result("NOT_OBSERVED", mode + "token_endpoint outside allowed scope")
    except Exception as e:
        return result("NOT_OBSERVED", mode + "token request failed: %s" % type(e).__name__)
    finally:
        req = None

    tokens = []
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        doc = None
    if isinstance(doc, dict):
        for hint in ("access_token", "refresh_token"):
            if isinstance(doc.get(hint), str) and doc[hint]:
                tokens.append((hint, doc[hint]))
    doc = None
    recorded_body = redact_secrets(body)
    body = None
    obtained = any(h == "access_token" for h, _ in tokens)
    revocation = _revoke_tokens(metadata, client, tokens) if tokens else "nothing to revoke"
    del tokens[:]

    acao = _header(headers, "access-control-allow-origin").strip()
    acac = _header(headers, "access-control-allow-credentials").strip().lower() == "true"
    seen = "HTTP %d token response, %s; ACAO: %s, ACAC: %s (hostile Origin sent: %s); revocation: %s" % (
        http_status, "access token obtained" if obtained else "no access token in the response",
        acao or "(absent)", "true" if acac else "(absent)", HOSTILE_ORIGIN, revocation)
    severity = None
    if 200 <= http_status < 300 and acao == "*":
        status, severity = "FAIL", ("CRITICAL" if acac else "HIGH")
    elif 200 <= http_status < 300 and not acao:
        status = "PASS"
    else:
        status = "NOT_OBSERVED"
    return result(status, mode + seen, http_status=http_status, headers=headers, body=recorded_body,
                  severity=severity)


def probe_token_cors(token_endpoint, metadata=None, client=None, registration_note=None):
    """Token endpoint must not expose credentials to cross-origin requests.

    Default: one POST with a hostile Origin and no authorization code. With ACQUIRE_TOKEN
    (--acquire-token) and metadata given, _token_cors_acquired obtains a real token first.
    """
    if token_endpoint and ACQUIRE_TOKEN and metadata is not None:
        return _token_cors_acquired(token_endpoint, metadata, client, registration_note)
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
    acac = ""
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
            acac = next((v for k, v in headers.items() if k.lower() == "access-control-allow-credentials"), "")
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
        # Severity from what the response allowed, not from what the scanner sent:
        # echoed origin + Allow-Credentials true lets a hostile page read a credentialed response.
        if acao == origin_sent and acac.strip().lower() == "true":
            severity = "CRITICAL"
        else:
            severity = "HIGH"
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
            detail = "ACAO: %s, ACAC: %s (hostile Origin sent: %s)" % (acao, acac or "(absent)", origin_sent)
    elif status == "PASS" and acao == "":
        detail = "HTTP %d token response with no Access-Control-Allow-Origin header" % http_status
    elif status == "PASS":
        detail = "HTTP %d token response; ACAO %s does not admit hostile Origin %s" % (http_status, acao, origin_sent)
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
    except EgressRefusalError:
        return record(
            probe_id=6,
            name="password-grant",
            status="NOT_OBSERVED",
            probe_class="authserver",
            detail="Target URL outside allowed scope"
        )
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
    elif 400 <= http_status < 500 and error in ("unsupported_grant_type", "unauthorized_client"):
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


_REDACTED_PARAMS = ("code", "access_token", "id_token")


def _redact_location(location):
    """Location as recorded: authorization codes and tokens are replaced, never stored."""
    if not location:
        return location
    parts = urlsplit(location)
    def scrub(qs):
        pairs = parse_qsl(qs, keep_blank_values=True)
        if not any(k in _REDACTED_PARAMS for k, _ in pairs):
            return qs
        return "&".join("%s=%s" % (k, "[redacted]" if k in _REDACTED_PARAMS else v) for k, v in pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, scrub(parts.query), scrub(parts.fragment)))


def _same_uri(location, uri):
    """Location targets uri exactly, optionally followed by its own query or fragment."""
    if not uri:
        return False
    if location == uri:
        return True
    return location.startswith(uri + ("&" if "?" in uri else "?")) or location.startswith(uri + "#")


def _origin(url):
    parts = urlsplit(url)
    return (parts.scheme.lower(), (parts.hostname or "").lower(), parts.port)


def _authorize(authorization_endpoint, params):
    """One authorization request. Redirects are never followed and the Location is never fetched."""
    sep = "&" if "?" in authorization_endpoint else "?"
    req = Request(authorization_endpoint + sep + urlencode(params), method="GET")
    req.add_header("User-Agent", "mcp-authscan/2.0.0")
    return _egress_guard(req, follow_redirects=False)


def _classify(response, authorization_endpoint, sent_redirect_uri, registered_redirect_uri):
    """Return (outcome, summary, recorded_location); outcome is proceeded, refused or neither.

    proceeded: HTTP 200; or a 3xx whose Location is the redirect_uri that was sent, or a
               consent page on the authorization endpoint's own origin; no error= either way.
    refused:   a 4xx whose JSON body carries "error"; or a 3xx whose Location carries error=.
    neither:   anything else, including a 3xx to the registered redirect_uri when a different
               one was sent (the server substituted it; acceptance of the sent value is not shown).
    """
    status, headers, body = response
    location = headers.get("Location") if headers is not None else None
    if 300 <= status < 400:
        if not location:
            return "neither", "HTTP %d with no Location" % status, None
        absolute = urljoin(authorization_endpoint, location)
        recorded = _redact_location(absolute)
        parts = urlsplit(absolute)
        params = dict(parse_qsl(parts.query)) | dict(parse_qsl(parts.fragment))
        if "error" in params:
            return "refused", "HTTP %d, Location %s (error=%s)" % (status, recorded, params["error"]), recorded
        if _same_uri(absolute, sent_redirect_uri):
            return "proceeded", "HTTP %d, Location %s (the redirect_uri sent)" % (status, recorded), recorded
        if registered_redirect_uri and _same_uri(absolute, registered_redirect_uri):
            return ("neither", "HTTP %d, Location %s (the registered redirect_uri, not the one sent)"
                    % (status, recorded), recorded)
        if _origin(absolute) == _origin(authorization_endpoint):
            return "proceeded", "HTTP %d, Location %s (consent page on the authorization server's origin)" % (status, recorded), recorded
        return "neither", "HTTP %d, Location %s (neither the redirect_uri nor the server's own origin)" % (status, recorded), recorded
    if status == 200:
        return "proceeded", "HTTP 200", None
    if 400 <= status < 500:
        try:
            doc = json.loads((body or b"").decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            doc = None
        if isinstance(doc, dict) and doc.get("error"):
            return "refused", "HTTP %d, error=%s" % (status, doc["error"]), None
        return "neither", "HTTP %d without a JSON error body" % status, None
    return "neither", "HTTP %d" % status, None


def _pkce_challenge():
    """A fresh S256 code_challenge: 43 characters, base64url of SHA-256 over a random verifier."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _verdict_record(probe_id, name, status, response, recorded_location, detail, severity, endpoint):
    """PASS/FAIL record for an authorize probe: evidence is the deciding response's status and Location."""
    http_status, _, body = response
    return record(
        probe_id=probe_id,
        name=name,
        status=status,
        http_status=http_status,
        headers={"Location": recorded_location} if recorded_location else {},
        body=body,
        evidence="headers",
        probe_class="authserver",
        detail=detail,
        severity=severity,
        endpoint=endpoint,
    )


def probe_pkce_s256(metadata, client=None, registration_note=None):
    """PKCE must be required, and S256 must be the only accepted method.

    A: no code_challenge. B: S256 challenge. C: the same challenge with method plain.
    The three requests differ only in PKCE. Redirects are never followed.
    client: a registered client (run_oauth_assessment); None reads the environment.
    registration_note: why registration supplied no client, recorded as detail if EXCLUDED.
    """
    authorization_endpoint = (metadata or {}).get("authorization_endpoint")
    if not authorization_endpoint:
        return record(probe_id=7, name="pkce-s256", status="EXCLUDED", probe_class="authserver",
                      prerequisites=["authorization_endpoint"], prerequisite_met=False,
                      limitation="No authorization endpoint")
    if client is not None:
        client_id, redirect_uri = client.client_id, client.redirect_uri
    else:
        client_id, _, redirect_uri = _client_creds()
    if not client_id:
        return record(probe_id=7, name="pkce-s256", status="EXCLUDED", probe_class="authserver",
                      prerequisites=["client_id"], prerequisite_met=False,
                      limitation="No client_id to build an authorization request (MCPAUTHSCAN_CLIENT_ID not set)",
                      detail=registration_note)

    base = {"response_type": "code", "client_id": client_id}
    if redirect_uri:
        base["redirect_uri"] = redirect_uri
    challenge = _pkce_challenge()
    requests_sent = [
        ("A (no code_challenge)", dict(base)),
        ("B (S256)", dict(base, code_challenge=challenge, code_challenge_method="S256")),
        ("C (plain)", dict(base, code_challenge=challenge, code_challenge_method="plain")),
    ]
    results = []

    def summary():
        return "; ".join("%s: %s, %s" % (label, outcome, text) for label, outcome, text, _, _ in results)

    for index, (label, params) in enumerate(requests_sent):
        if index == 2 and not (results[0][1] == "refused" and results[1][1] == "proceeded"):
            break
        try:
            response = _authorize(authorization_endpoint, params)
        except EgressRefusalError:
            return record(probe_id=7, name="pkce-s256", status="NOT_OBSERVED", probe_class="authserver",
                          detail="Target URL outside allowed scope", endpoint=authorization_endpoint)
        except Exception as e:
            return record(probe_id=7, name="pkce-s256", status="NOT_OBSERVED", probe_class="authserver",
                          detail="Request %s failed: %s%s" % (label, e, ("; " + summary()) if results else ""),
                          endpoint=authorization_endpoint)
        outcome, text, recorded = _classify(response, authorization_endpoint, redirect_uri, redirect_uri)
        results.append((label, outcome, text, response, recorded))

    if len(results) < 3:
        return record(probe_id=7, name="pkce-s256", status="NOT_OBSERVED", probe_class="authserver",
                      detail="PKCE requirement not demonstrated (needs A refused and B proceeded): " + summary(),
                      endpoint=authorization_endpoint)
    _, c_outcome, _, c_response, c_location = results[2]
    if c_outcome == "refused":
        return _verdict_record(7, "pkce-s256", "PASS", c_response, c_location,
                               "PKCE required and S256 the only accepted method: " + summary(),
                               None, authorization_endpoint)
    if c_outcome == "proceeded":
        return _verdict_record(7, "pkce-s256", "FAIL", c_response, c_location,
                               "The server accepted an authorization request using the PKCE plain method. "
                               + summary() + ". Nothing was sent to the returned Location.",
                               "HIGH", authorization_endpoint)
    return record(probe_id=7, name="pkce-s256", status="NOT_OBSERVED", probe_class="authserver",
                  detail="plain method neither refused nor accepted: " + summary(),
                  endpoint=authorization_endpoint)


def _near_match(redirect_uri):
    """The registered redirect_uri with one character appended to its path."""
    parts = urlsplit(redirect_uri)
    path = parts.path or "/"
    return urlunsplit((parts.scheme, parts.netloc, path + "x", parts.query, parts.fragment))


def probe_redirect_uri_exact(metadata, client=None, registration_note=None):
    """redirect_uri must match the registered value exactly.

    P: the registered redirect_uri. N: the same URI with one character appended to its path.
    Both carry a valid S256 challenge so PKCE cannot be the cause. Redirects are never followed.
    client: a registered client (run_oauth_assessment); None reads the environment.
    registration_note: why registration supplied no client, recorded as detail if EXCLUDED.
    """
    authorization_endpoint = (metadata or {}).get("authorization_endpoint")
    if not authorization_endpoint:
        return record(probe_id=8, name="redirect-uri-exact", status="EXCLUDED", probe_class="authserver",
                      prerequisites=["authorization_endpoint"], prerequisite_met=False,
                      limitation="No authorization endpoint")
    if client is not None:
        client_id, redirect_uri = client.client_id, client.redirect_uri
    else:
        client_id, _, redirect_uri = _client_creds()
    if not client_id or not redirect_uri:
        return record(probe_id=8, name="redirect-uri-exact", status="EXCLUDED", probe_class="authserver",
                      prerequisites=["client_id", "redirect_uri"], prerequisite_met=False,
                      limitation="No registered redirect_uri to compare against",
                      detail=registration_note)

    near = _near_match(redirect_uri)
    results = []

    def summary():
        return "; ".join("%s: %s, %s" % (label, outcome, text) for label, outcome, text, _, _ in results)

    for label, sent in (("P (registered redirect_uri)", redirect_uri), ("N (%s)" % near, near)):
        if results and results[0][1] != "proceeded":
            break
        params = {"response_type": "code", "client_id": client_id, "redirect_uri": sent,
                  "code_challenge": _pkce_challenge(), "code_challenge_method": "S256"}
        try:
            response = _authorize(authorization_endpoint, params)
        except EgressRefusalError:
            return record(probe_id=8, name="redirect-uri-exact", status="NOT_OBSERVED", probe_class="authserver",
                          detail="Target URL outside allowed scope", endpoint=authorization_endpoint)
        except Exception as e:
            return record(probe_id=8, name="redirect-uri-exact", status="NOT_OBSERVED", probe_class="authserver",
                          detail="Request %s failed: %s%s" % (label, e, ("; " + summary()) if results else ""),
                          endpoint=authorization_endpoint)
        outcome, text, recorded = _classify(response, authorization_endpoint, sent, redirect_uri)
        results.append((label, outcome, text, response, recorded))

    p_outcome = results[0][1]
    if p_outcome == "refused":
        return record(probe_id=8, name="redirect-uri-exact", status="NOT_OBSERVED", probe_class="authserver",
                      detail="No baseline: the registered redirect_uri was refused: " + summary(),
                      endpoint=authorization_endpoint)
    if p_outcome != "proceeded":
        return record(probe_id=8, name="redirect-uri-exact", status="NOT_OBSERVED", probe_class="authserver",
                      detail="No baseline: the registered redirect_uri neither proceeded nor was refused: " + summary(),
                      endpoint=authorization_endpoint)
    _, n_outcome, _, n_response, n_location = results[1]
    if n_outcome == "refused":
        return _verdict_record(8, "redirect-uri-exact", "PASS", n_response, n_location,
                               "Exact redirect_uri match enforced: " + summary(),
                               None, authorization_endpoint)
    if n_outcome == "proceeded":
        return _verdict_record(8, "redirect-uri-exact", "FAIL", n_response, n_location,
                               "The server accepted a redirect_uri with one character appended to the registered "
                               "path, so it does not compare redirect URIs exactly. " + summary()
                               + ". Nothing was sent to the returned Location.",
                               "CRITICAL", authorization_endpoint)
    return record(probe_id=8, name="redirect-uri-exact", status="NOT_OBSERVED", probe_class="authserver",
                  detail="Near-match redirect_uri neither refused nor accepted: " + summary(),
                  endpoint=authorization_endpoint)


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
    elif 400 <= http_status < 500 and error in ("invalid_client", "unauthorized_client"):
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

    # Client source for probes 7 and 8: dynamic registration, else the environment, else EXCLUDED.
    registered, registration = _register_client(metadata)
    client = registered if registered is not None and registered.usable else None
    registration_note = None if client else "Dynamic client registration unavailable: " + registration

    records = []
    records.append(probe_issuer_identity(metadata_url, metadata))
    rb = probe_resource_binding(resource_metadata, mcp_url)
    if rb:
        records.append(rb)
    records.append(probe_token_cache_control(metadata.get("token_endpoint")))
    records.append(probe_token_cors(metadata.get("token_endpoint"), metadata=metadata, client=client,
                                    registration_note=registration_note))
    records.append(probe_jwks_keys(metadata.get("jwks_uri")))
    records.append(probe_password_grant(metadata.get("token_endpoint")))
    records.append(probe_pkce_s256(metadata, client=client, registration_note=registration_note))
    records.append(probe_redirect_uri_exact(metadata, client=client, registration_note=registration_note))
    records.append(probe_client_auth(metadata.get("token_endpoint")))

    # Revoke a registered client after the last probe that uses it, before anything is reported.
    revocation = _revoke_client(metadata, registered) if registered is not None else \
        "not applicable: no client was registered"
    if client is not None:
        source, client_id, redirect_uri = "registered", client.client_id, client.redirect_uri
    else:
        env_id, _, env_redirect = _client_creds()
        if env_id:
            source, client_id = "environment (MCPAUTHSCAN_CLIENT_ID)", env_id
            redirect_uri = env_redirect or "(none: MCPAUTHSCAN_REDIRECT_URI not set)"
        else:
            source, client_id, redirect_uri = "none", None, "(none)"
    CLIENT_REPORTS.append({
        "authorization_server": oauth_server_url,
        "client_registered": registered is not None,
        "registration": registration,
        "client_source": source,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "revocation": revocation,
    })
    registered = client = None
    return records, []


def count_probes(records):
    """Count probe results."""
    from .counts import count_probes as _count
    return _count(records)


def render_probe(record):
    """Format probe for stderr display."""
    return "[%d] %-20s %s" % (record.probe_id, record.name, record.status)
