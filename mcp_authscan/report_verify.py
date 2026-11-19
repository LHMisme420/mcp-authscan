"""Shared schema-3 report projection and byte serialization for CLI and web."""
import hashlib
import json
import re

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
EVIDENCE_SCHEME_V1 = "evidence-binding-v1"   # entries {access_class, state_id}
EVIDENCE_SCHEME = "evidence-binding-v2"      # entries {access_class, state_id, ledger, ledger_head}
_ENTRY_KEYS = {
    EVIDENCE_SCHEME_V1: ["access_class", "state_id"],
    EVIDENCE_SCHEME: ["access_class", "ledger", "ledger_head", "state_id"],
}
_ACCESS_CLASSES = ("anonymous", "authenticated")
_LEDGER_KEY = re.compile(r"^[A-Za-z0-9._-]+/(anonymous|authenticated)\.jsonl$")


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def evidence_binding(payload):
    """Return the validated evidence binding, or None if the report has none.

    The binding names the security-state-v1 STATE IDs this report was
    produced alongside and, in v2, the ledger chain each was recorded in:
    ``ledger`` is the chain's key under the ledger root (null when no row was
    recorded) and ``ledger_head`` the chain head before this run (null for a
    new or absent chain). It is outside report_hash (graded content only) and
    inside the signature. Raises ValueError if present but malformed.
    """
    if EVIDENCE_KEY not in payload:
        return None
    ev = payload[EVIDENCE_KEY]
    if not isinstance(ev, dict) or sorted(ev) != ["scheme", "states"] or ev["scheme"] not in _ENTRY_KEYS:
        raise ValueError(f"evidence must be {{scheme: {EVIDENCE_SCHEME} or {EVIDENCE_SCHEME_V1}, states: [...]}}")
    keys = _ENTRY_KEYS[ev["scheme"]]
    states = ev["states"]
    if not isinstance(states, list):
        raise ValueError("evidence.states must be a list")
    classes = []
    for entry in states:
        if (not isinstance(entry, dict) or sorted(entry) != keys
                or entry["access_class"] not in _ACCESS_CLASSES or not _hex64(entry["state_id"])):
            raise ValueError(f"evidence.states entries must be {{{', '.join(keys)}}}")
        if ev["scheme"] == EVIDENCE_SCHEME:
            ledger, head = entry["ledger"], entry["ledger_head"]
            if ledger is not None and (not isinstance(ledger, str) or not _LEDGER_KEY.match(ledger)
                                       or not ledger.endswith(f"/{entry['access_class']}.jsonl")):
                raise ValueError("evidence.states ledger must be null or <chain>/<access_class>.jsonl")
            if head is not None and not _hex64(head):
                raise ValueError("evidence.states ledger_head must be null or 64 lowercase hex")
            if ledger is None and head is not None:
                raise ValueError("evidence.states ledger_head requires a ledger")
        classes.append(entry["access_class"])
    if classes != sorted(set(classes)):
        raise ValueError("evidence.states must be sorted by access_class with no duplicates")
    return ev


SIG_VERSION_KEY = "sig_version"
SIG_VERSION_GRADED = 1     # signed bytes: canonical graded report (the report_hash preimage)
SIG_VERSION_EVIDENCE = 2   # signed bytes: canonical {"sig_version": 2, "evidence": ..., "report": ...}
SIG_VERSIONS = (SIG_VERSION_GRADED, SIG_VERSION_EVIDENCE)


def sig_version_for(payload):
    """The sig_version a new signature over ``payload`` must declare."""
    return SIG_VERSION_EVIDENCE if EVIDENCE_KEY in payload else SIG_VERSION_GRADED


def signed_content(payload, findings):
    """The exact bytes a report signature covers, chosen by the report's sig_version.

    sig_version absent or 1: the canonical graded report bytes, identical to
    the report_hash preimage. Every report signed before sig_version existed
    is form 1. An evidence field is not allowed in form 1, because form 1
    does not cover it.
    sig_version 2: canonical JSON of {"sig_version": 2, "evidence": binding,
    "report": canonical graded report}. The evidence binding is required.

    The form is read from sig_version, never inferred from which fields are
    present. Raises ValueError for an unknown sig_version or a mismatch.
    """
    version = payload.get(SIG_VERSION_KEY, SIG_VERSION_GRADED)
    if isinstance(version, bool) or version not in SIG_VERSIONS:
        raise ValueError(f"sig_version: unknown value {version!r}")
    canonical = canonical_report(payload, findings)
    ev = evidence_binding(payload)
    if version == SIG_VERSION_GRADED:
        if ev is not None:
            raise ValueError("sig_version: 1 does not cover an evidence field; evidence requires sig_version 2")
        return serialize(canonical)
    if ev is None:
        raise ValueError("sig_version: 2 requires an evidence field")
    return serialize({SIG_VERSION_KEY: version, EVIDENCE_KEY: ev, "report": canonical})


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
