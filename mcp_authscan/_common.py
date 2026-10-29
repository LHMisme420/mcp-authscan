"""Shared probe infrastructure: record factory, HTTP client, constants."""
import hashlib
import json
import re


VALID_STATUSES = {"PASS", "FAIL", "NOT_OBSERVED", "EXCLUDED", "NOT_IMPLEMENTED"}
SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# Response fields whose values are credentials. Their values are never recorded.
SECRET_FIELDS = ("access_token", "refresh_token", "id_token", "client_secret", "registration_access_token")
_SECRET_JSON = re.compile(r'("(?:%s)"\s*:\s*)"(?:[^"\\]|\\.)*"' % "|".join(SECRET_FIELDS))
_SECRET_FORM = re.compile(r'((?:^|[?&#])(?:%s)=)[^&#\s]*' % "|".join(SECRET_FIELDS))


def redact_secrets(body):
    """body (bytes) with the value of every SECRET_FIELDS member replaced by "[redacted]".

    A JSON object is re-serialised with those keys' values replaced at any depth; anything else
    has JSON-style "key": "value" pairs and form-style key=value pairs replaced in place.
    """
    if not body:
        return body or b""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        doc = None

    def scrub(node):
        if isinstance(node, dict):
            return {k: ("[redacted]" if k in SECRET_FIELDS else scrub(v)) for k, v in node.items()}
        if isinstance(node, list):
            return [scrub(v) for v in node]
        return node

    if isinstance(doc, (dict, list)):
        return json.dumps(scrub(doc)).encode("utf-8")
    text = body.decode("utf-8", "replace")
    text = _SECRET_JSON.sub(r'\1"[redacted]"', text)
    text = _SECRET_FORM.sub(r"\1[redacted]", text)
    return text.encode("utf-8")


def record(probe_id, name, status, *, http_status=None, headers=None, body=b"",
           prerequisites=(), prerequisite_met=True, limitation=None,
           probe_class=None, detail=None, evidence="body",
           severity=None, endpoint=None):
    """Build a ProbeRecord, refusing any record that is not backed by evidence."""
    from .oauth_probes_v2 import ProbeRecord
    
    if status not in VALID_STATUSES:
        raise ValueError("probe %s: illegal status %r" % (probe_id, status))
    if not prerequisite_met and status != "EXCLUDED":
        raise ValueError(
            "probe %s: unmet prerequisite must be EXCLUDED, got %s" % (probe_id, status))
    body = body or b""
    if status in ("PASS", "FAIL"):
        if http_status is None:
            raise ValueError("probe %s: %s needs a real http status" % (probe_id, status))
        if evidence == "body" and not body:
            raise ValueError("probe %s: %s needs a real response body" % (probe_id, status))
    if status == "FAIL":
        if severity not in SEVERITY_ORDER:
            raise ValueError("probe %s: FAIL needs a severity from %s, got %r"
                             % (probe_id, list(SEVERITY_ORDER), severity))
        if not endpoint:
            raise ValueError("probe %s: FAIL needs the endpoint it was observed on"
                             % probe_id)
    return ProbeRecord(
        probe_id=probe_id,
        name=name,
        status=status,
        http_status=http_status,
        headers_observed={k.lower(): v for k, v in (headers or {}).items()},
        body_excerpt=body[:2048].decode("utf-8", "replace") if body else "",
        body_sha256=hashlib.sha256(body).hexdigest() if body else None,
        prerequisites=list(prerequisites),
        prerequisite_met=prerequisite_met,
        limitation=limitation,
        probe_class=probe_class,
        detail=detail,
        severity=severity,
        endpoint=endpoint,
    )


def send(session, method, url, **kw):
    """Returns (response, error). Never raises, never hides a failure."""
    import requests
    kw.setdefault("timeout", 10)
    kw.setdefault("allow_redirects", False)
    try:
        return session.request(method, url, **kw), None
    except requests.RequestException as exc:
        return None, "%s: %s" % (type(exc).__name__, exc)
