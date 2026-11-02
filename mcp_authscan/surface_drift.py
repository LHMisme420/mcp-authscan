"""Drift findings between a pinned MCP surface and the current one."""
from .surface import build_baseline, drift_report, load_baseline, save_baseline
from .surface_capture import capture_surface

DRIFT_RULE = "MCPD-1"
DRIFT_SEVERITY = "medium"
EXCERPT_LIMIT = 240

TITLES = {
    "added": "MCP surface item added since baseline",
    "removed": "MCP surface item removed since baseline",
    "changed": "MCP surface item changed since baseline",
    "whitespace": "MCP surface item reformatted since baseline",
}


import re

BEARER = re.compile(r"(?i)bearer\s+[A-Za-z0-9\-.~+/]+=*")
NAMED_KEY = re.compile(r"(?i)(api[-]?key|token|secret|password|passwd|authorization)(\s*[:=]\s*)\S+")
LONG_TOKEN = re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def scrub_text(text):
    text = BEARER.sub("bearer [redacted]", text)
    text = NAMED_KEY.sub(lambda m: m.group(1) + m.group(2) + "[redacted]", text)
    text = LONG_TOKEN.sub("[redacted]", text)
    text = EMAIL.sub("[redacted email]", text)
    return text


def excerpt(value):
    text = scrub_text(str(value if value is not None else ""))
    if len(text) <= EXCERPT_LIMIT:
        return text
    return text[:EXCERPT_LIMIT] + "..."


def field_excerpt(row, fields):
    if isinstance(row, str):
        return excerpt(row)
    if not isinstance(row, dict):
        return ""
    if not fields:
        fields = sorted(row.keys())
    parts = []
    for field in fields:
        if field in row:
            parts.append("%s: %s" % (field, excerpt(row.get(field))))
    return "; ".join(parts)


def change_evidence(change):
    kind = change.get("change")
    fields = change.get("fields") or []
    if kind == "added":
        return "new item: " + field_excerpt(change.get("after"), [])
    if kind == "removed":
        return "previous item: " + field_excerpt(change.get("before"), [])
    return "before: %s | after: %s" % (field_excerpt(change.get("before"), fields), field_excerpt(change.get("after"), fields))


def drift_findings(endpoint, outcome):
    findings = []
    for change in outcome.get("changes") or []:
        title = TITLES.get(change.get("change"), "MCP surface changed since baseline")
        findings.append({
            "rule": DRIFT_RULE,
            "owasp": None,
            "severity": DRIFT_SEVERITY,
            "confidence": "HIGH",
            "title": "%s: %s" % (title, change.get("key") or ""),
            "file": endpoint,
            "line": 0,
            "ref": change.get("key") or "",
            "evidence": change_evidence(change),
            "snippet": "",
        })
    return findings


def run_surface_drift(endpoint, baseline_path, allow_private=None, allowed_hosts=None, token=None):
    if not baseline_path:
        return [], None
    captured = capture_surface(endpoint, token, allow_private, allowed_hosts)
    baseline, error = load_baseline(baseline_path)
    if baseline is None:
        doc = build_baseline(endpoint, captured)
        save_baseline(baseline_path, doc)
        return [], {"state": "pinned", "baseline": baseline_path, "digest": doc.get("digest"), "reason": error, "changes": 0}
    outcome = drift_report(endpoint, captured, baseline)
    changes = outcome.get("changes") or []
    record = {"state": outcome.get("state"), "baseline": baseline_path, "digest": captured.get("digest"), "reason": outcome.get("reason"), "changes": len(changes)}
    return drift_findings(endpoint, outcome), record
