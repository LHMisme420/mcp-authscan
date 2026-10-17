"""Evidence-based CORS policy shared by live scanner entry points.

Payload heuristics are conservative evidence, not proof that an API is public.
Response values and cookie values are never included in reported details.
"""
import json
import re
from dataclasses import dataclass
from typing import Mapping
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

MAX_BODY = 65536
SECRET_FIELDS = {
    "password", "password_hash", "access_token", "refresh_token", "id_token",
    "api_key", "api_secret", "client_secret", "private_key", "ssn",
    "social_security_number", "credit_card_number", "bank_account_number",
}
PROFILE_FIELDS = {"email", "address", "phone", "date_of_birth", "dob"}
PROFILE_CONTAINERS = {"user", "users", "current_user", "profile", "account", "accounts"}
AUTH_COOKIE = re.compile(
    r"(?:^|[;,]\s*)(?:session|sessionid|session_id|sid|connect\.sid|"
    r"auth|auth_token|session_token|access_token|jwt)\s*=", re.I
)
AUTH_HEADERS = {
    "authorization", "x-api-key", "api-key", "apikey", "x-auth-token",
    "x-access-token", "x-api-token", "x-authorization",
}
AUTH_QUERY_FIELDS = {
    "api_key", "apikey", "access_token", "auth_token", "token", "key",
    "client_secret", "signature", "sig",
}


@dataclass
class CorsResponse:
    headers: Mapping[str, str]
    body: bytes = b""
    status: int = 200
    request_cookie: str = ""
    cookie_authenticated: bool = False
    request_authenticated: bool = False


@dataclass
class CorsAssessment:
    is_finding: bool
    severity: str
    summary: str
    details: str
    remediation: str
    reflected: bool = False


def _headers(response):
    result = {}
    for key, value in response.headers.items():
        key = str(key).lower()
        result[key] = (result[key] + ", " if key in result else "") + str(value).strip()
    return result


def _request_has_auth(headers, url):
    """Record credential presence only, never credential values."""
    parsed = urlparse(url)
    return (
        any(str(key).lower() in AUTH_HEADERS and bool(value) for key, value in headers.items())
        or bool(parsed.username or parsed.password)
        or any(key.lower() in AUTH_QUERY_FIELDS and bool(value)
               for key, value in parse_qsl(parsed.query))
    )


def _anonymous_success(response):
    return (
        200 <= response.status < 300
        and not response.request_authenticated
        and not response.cookie_authenticated
        and not response.request_cookie
    )


def sensitive_user_data(body):
    """Recognize populated secret fields or personal fields within user records.

    Public tool discovery, schemas, arbitrary strings, and empty responses do
    not establish sensitive user data. Non-JSON formats remain inconclusive.
    """
    text = body[:MAX_BODY].decode("utf-8", errors="replace")
    candidates = [text] + [
        line[5:].strip() for line in text.splitlines()[:100] if line.startswith("data:")
    ]

    def populated(value):
        if isinstance(value, str):
            return bool(value.strip())
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    def walk(value, in_profile=False, depth=0):
        if depth > 16:
            return False
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", str(key))
                normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", normalized).lower().replace("-", "_")
                if normalized in SECRET_FIELDS and populated(item):
                    return True
                if in_profile and normalized in PROFILE_FIELDS and populated(item):
                    return True
                if walk(item, in_profile or normalized in PROFILE_CONTAINERS, depth + 1):
                    return True
        elif isinstance(value, list):
            return any(walk(item, in_profile, depth + 1) for item in value[:100])
        return False

    for candidate in candidates:
        try:
            if walk(json.loads(candidate)):
                return True
        except (ValueError, RecursionError):
            continue
    return False


def assess_cors(observations):
    """Evaluate (sent Origin, response) pairs; reflection requires two probes."""
    headers = [_headers(response) for _, response in observations]
    wildcard = any(item.get("access-control-allow-origin") == "*" for item in headers)
    reflected = (
        len(observations) >= 2
        and observations[0][0] != observations[1][0]
        and all(
            item.get("access-control-allow-origin") == origin
            for (origin, _), item in zip(observations, headers)
        )
    )
    sensitive_responses = [
        200 <= response.status < 300 and sensitive_user_data(response.body)
        for _, response in observations
    ]
    credential_responses = [item.get("access-control-allow-credentials", "").lower() == "true" for item in headers]
    cookie_indicators = [
        bool(AUTH_COOKIE.search(item.get("set-cookie", "") + ";" + response.request_cookie))
        for (_, response), item in zip(observations, headers)
    ]
    cookie_responses = [
        response.cookie_authenticated
        or item.get("www-authenticate", "").lower().startswith("cookie")
        for (_, response), item in zip(observations, headers)
    ]
    sensitive = any(sensitive_responses)
    credentials = any(credential_responses)
    cookie_auth = any(cookie_responses)
    details = (
        f"Wildcard: {wildcard}; arbitrary Origin reflection: {reflected}; "
        f"sensitive user-data evidence: {sensitive}; "
        f"session/auth-cookie indicators: {any(cookie_indicators)}; "
        f"cookie authentication verified or advertised: {cookie_auth}; "
        f"Allow-Credentials: {credentials}; "
        f"response statuses: {[response.status for _, response in observations]}; "
        f"request credentials present: {any(response.request_authenticated or bool(response.request_cookie) or response.cookie_authenticated for _, response in observations)}. "
    )
    if observations and all(response.status in {401, 403} for _, response in observations):
        return CorsAssessment(
            False, "INFO", "Authentication required; no CORS finding",
            details + "401/403 responses are protected for this assessment, "
            "even when Origin is reflected or Allow-Credentials is true.",
            "No CORS remediation indicated by this probe.", reflected=reflected,
        )
    if reflected and all(
        _anonymous_success(response) and private
        for (_, response), private in zip(observations, sensitive_responses)
    ):
        credentialed_sensitive = any(
            private and credentialed
            for private, credentialed in zip(sensitive_responses, credential_responses)
        )
        severity = "HIGH" if credentialed_sensitive else "MEDIUM" if sensitive else "LOW"
        return CorsAssessment(
            True, severity, "Unvalidated Origin reflection",
            details + "Two different origins received sensitive data in successful "
            "responses without request credentials.",
            "Validate Origin against an explicit allowlist before returning CORS headers.",
            reflected=True,
        )
    if any(
        item.get("access-control-allow-origin") == "*" and private and (cookie or credentialed)
        for item, private, cookie, credentialed in zip(
            headers, sensitive_responses, cookie_responses, credential_responses
        )
    ):
        return CorsAssessment(
            True, "MEDIUM", "Wildcard CORS on a sensitive response",
            details + "A cookie name alone is not authentication evidence. Browsers reject wildcard "
            "CORS for credentialed requests; this is a configuration risk, not confirmed data theft.",
            "Use an explicit trusted-origin allowlist for sensitive, credentialed endpoints.",
        )
    return CorsAssessment(
        False, "INFO", "No evidence-backed CORS vulnerability",
        details + (
            "Wildcard alone is not a finding: sensitive data with cookie/credential context "
            "was not established on the same wildcard response. "
            "Public header-token APIs may intentionally use wildcard CORS."
            if wildcard else "Origin reflection is not a vulnerability under this policy unless "
            "both probes successfully access sensitive data without authentication. "
            "Authenticated, protected, public-data, and unsuccessful responses are excluded."
        ),
        "Review unknown data/authentication context manually; public token APIs may retain wildcard CORS.",
        reflected=reflected,
    )


def probe_cors(fetch):
    """Probe only the authorized target; Origin hostnames are never contacted."""
    origin = f"https://cors-{uuid4().hex}.invalid"
    first = fetch(origin)
    observations = [(origin, first)]
    if (
        _headers(first).get("access-control-allow-origin") == origin
        and _anonymous_success(first)
        and sensitive_user_data(first.body)
    ):
        second_origin = f"https://cors-{uuid4().hex}.example"
        observations.append((second_origin, fetch(second_origin)))
    return assess_cors(observations)


def probe_cors_requests(url, method="GET", timeout=5, session=None):
    if session is None:
        import requests
        session = requests

    anonymous_probe_started = False

    def fetch(origin):
        nonlocal anonymous_probe_started
        kwargs = {
            "headers": {"Origin": origin, "Accept": "application/json, text/event-stream"},
            "timeout": timeout,
        }
        if anonymous_probe_started:
            # Do not let a Set-Cookie from the first anonymous response
            # turn the reflection confirmation into an authenticated request.
            kwargs["headers"]["Cookie"] = ""
        if method == "POST":
            kwargs["json"] = {"jsonrpc": "2.0", "method": "tools/list", "id": 1}
        response = session.request(method, url, **kwargs)
        request_headers = getattr(getattr(response, "request", None), "headers", {})
        body = response.content[:MAX_BODY]
        request_authenticated = _request_has_auth(request_headers, url)
        cookie_authenticated = False
        # Cookie names are not proof of authentication. Only establish this
        # context when the same sensitive response requires the sent cookies.
        if (
            response.headers.get("Access-Control-Allow-Origin") == "*"
            and 200 <= response.status_code < 300
            and request_headers.get("Cookie")
            and not request_headers.get("Authorization")
            and sensitive_user_data(body)
        ):
            import requests
            no_cookie_headers = {
                key: value for key, value in request_headers.items() if key.lower() != "cookie"
            }
            no_cookie_headers["Cookie"] = ""
            baseline_kwargs = dict(kwargs, headers=no_cookie_headers,
                                   verify=getattr(session, "verify", True))
            try:
                # Use a separate session so an anonymous Set-Cookie response
                # cannot overwrite the scanning session's cookies.
                baseline = requests.request(method, url, **baseline_kwargs)
                cookie_authenticated = (
                    baseline.status_code in {401, 403}
                    and not sensitive_user_data(baseline.content[:MAX_BODY])
                )
            except requests.RequestException:
                pass  # Unknown cookie context must not become a finding.
        snapshot = CorsResponse(
            response.headers, body, response.status_code,
            request_headers.get("Cookie", ""), cookie_authenticated, request_authenticated,
        )
        anonymous_probe_started = _anonymous_success(snapshot)
        return snapshot

    return probe_cors(fetch)


def probe_cors_urllib(url, method="GET", timeout=5, opener=None):
    opener = opener or urlopen

    def fetch(origin):
        request = Request(url, method=method, headers={"Origin": origin})
        if method == "POST":
            request.data = b'{"jsonrpc":"2.0","method":"tools/list","id":1}'
            request.add_header("Content-Type", "application/json")
        try:
            response = opener(request, timeout=timeout)
        except HTTPError as error:
            response = error
        with response:
            return CorsResponse(response.headers, response.read(MAX_BODY),
                                getattr(response, "status", getattr(response, "code", 200)),
                                request_cookie=request.get_header("Cookie", ""),
                                request_authenticated=_request_has_auth(dict(request.header_items()), url))

    return probe_cors(fetch)
