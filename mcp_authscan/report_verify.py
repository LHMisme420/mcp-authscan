"""Shared schema-3 report projection and byte serialization for CLI and web."""
import hashlib
import json

HASH_SCHEME = "verdict-v3"
SCHEMA_VERSION = 3
HASHED_KEYS = (
    "target", "status", "total_checks", "findings_count", "probe_set_version",
    "coverage", "severity_counts",
)
FINDING_KEYS = (
    "server_name", "rule", "vector_type", "severity", "severity_basis",
    "endpoint", "description", "remediation",
)


def serialize(payload):
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def severity_counts(findings):
    counts = {name: 0 for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    for finding in findings:
        name = str(finding.get("severity") or "UNKNOWN").upper()
        counts[name] = counts.get(name, 0) + 1
    return counts


def canonical_report(payload, findings):
    missing = [key for key in HASHED_KEYS if key not in payload]
    if missing:
        raise ValueError("Missing schema-3 fields: " + ",".join(missing))
    result = {key: payload[key] for key in HASHED_KEYS}
    # Sorting by covered content makes timestamps and database insertion order
    # irrelevant. Preserve duplicates: two identical findings still count twice.
    result["findings"] = sorted(
        ({key: finding.get(key) for key in FINDING_KEYS} for finding in findings),
        key=serialize,
    )
    if result["findings_count"] != len(result["findings"]):
        raise ValueError("Incomplete findings: schema-3 exports cannot truncate")
    if result["severity_counts"] != severity_counts(result["findings"]):
        raise ValueError("Severity counts do not match the complete findings")
    return result


def compute(payload, findings, *, include_bytes=False):
    canonical = canonical_report(payload, findings)
    # Serialize the projected report once. Signing receives these exact bytes,
    # not a second reconstruction of the report or its hexadecimal digest.
    content = serialize(canonical)
    result = hashlib.sha256(content).hexdigest(), sorted(canonical)
    return (*result, content) if include_bytes else result


def verify(path):
    with open(path, encoding="utf-8") as source:
        payload = json.load(source)
    if not payload.get("report_hash"):
        return "NOT_REPRODUCIBLE", "no report_hash in file"
    if payload.get("hash_scheme") != HASH_SCHEME or payload.get("schema_version") != SCHEMA_VERSION:
        return "NOT_REPRODUCIBLE", "requires verdict-v3 schema version 3; legacy hashes are not reinterpreted"
    try:
        got, covered = compute(payload, payload.get("findings") or [])
    except (ValueError, TypeError) as error:
        return "NOT_REPRODUCIBLE", str(error)
    if got == payload["report_hash"]:
        return "MATCH", got
    return "MISMATCH", "claimed %s, recomputed %s over %d covered fields" % (
        payload["report_hash"], got, len(covered),
    )
