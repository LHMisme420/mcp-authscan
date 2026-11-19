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


EVIDENCE_KEY = "evidence"
EVIDENCE_SCHEME = "evidence-binding-v1"
_ACCESS_CLASSES = ("anonymous", "authenticated")


def evidence_binding(payload):
    """Return the validated evidence binding, or None if the report has none.

    The binding names the security-state-v1 STATE IDs this report was
    produced alongside. It is outside report_hash (graded content only) and
    inside the signature. Raises ValueError if present but malformed.
    """
    if EVIDENCE_KEY not in payload:
        return None
    ev = payload[EVIDENCE_KEY]
    if not isinstance(ev, dict) or sorted(ev) != ["scheme", "states"] or ev["scheme"] != EVIDENCE_SCHEME:
        raise ValueError(f"evidence must be {{scheme: {EVIDENCE_SCHEME}, states: [...]}}")
    states = ev["states"]
    if not isinstance(states, list):
        raise ValueError("evidence.states must be a list")
    classes = []
    for entry in states:
        if (not isinstance(entry, dict) or sorted(entry) != ["access_class", "state_id"]
                or entry["access_class"] not in _ACCESS_CLASSES
                or not isinstance(entry["state_id"], str) or len(entry["state_id"]) != 64
                or any(c not in "0123456789abcdef" for c in entry["state_id"])):
            raise ValueError("evidence.states entries must be {access_class, state_id}")
        classes.append(entry["access_class"])
    if classes != sorted(set(classes)):
        raise ValueError("evidence.states must be sorted by access_class with no duplicates")
    return ev


def signed_content(payload, findings):
    """The exact bytes a report signature covers.

    No evidence binding: the canonical graded report bytes, identical to the
    report_hash preimage (unchanged from before evidence existed).
    With a binding: canonical JSON of {"evidence": binding, "report": canonical graded report}.
    Removing, adding or editing the binding therefore breaks the signature,
    while report_hash stays a function of graded content alone.
    """
    canonical = canonical_report(payload, findings)
    ev = evidence_binding(payload)
    if ev is None:
        return serialize(canonical)
    return serialize({EVIDENCE_KEY: ev, "report": canonical})


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
