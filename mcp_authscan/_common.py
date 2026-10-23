"""Shared probe infrastructure: record factory, HTTP client, constants."""
import hashlib


VALID_STATUSES = {"PASS", "FAIL", "NOT_OBSERVED", "EXCLUDED"}
SEVERITY_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


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
