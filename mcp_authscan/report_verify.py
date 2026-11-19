"""Shared schema-3 report projection and byte serialization for CLI and web."""
import hashlib
import json
import re
import sys

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


# ---- the pre-schema-3 format (releases 1.1.21 to 1.1.24) ---------------------------
#
# Those releases wrote hash_scheme "verdict-v3" with NO schema_version, and
# hashed a different key set with a different serialization. Their verifier
# was byte-identical across all four wheels on PyPI (sha256 2c87594ff614...).
# A report in that format is verified with that algorithm, reproduced
# verbatim below, and nothing else: it is never reinterpreted as schema 3,
# and schema-3 reports never take this path. Releases before 1.1.21 shipped
# no verifier. The format was never signed.
LEGACY_RELEASES = ("1.1.21", "1.1.22", "1.1.23", "1.1.24")
LEGACY_MATCH = "LEGACY_MATCH"
LEGACY_MISMATCH = "LEGACY_MISMATCH"
LEGACY_NOTE = "pre-1.1.25 algorithm, releases 1.1.21-1.1.24"
LEGACY_HASHED_KEYS = ("target", "scan_mode", "probe_set_version", "probes", "counts", "coverage", "completed",
                      "not_implemented", "not_tested", "scope", "exit_contract", "exit_condition", "exit_code",
                      "fail_on", "authorization", "hash_scheme")
LEGACY_FINDING_KEYS = ("severity", "rule", "title", "endpoint", "severity_basis")


def is_legacy(payload):
    """True for the pre-schema-3 format: verdict-v3 with no schema_version key at all."""
    return payload.get("hash_scheme") == HASH_SCHEME and "schema_version" not in payload


def compute_legacy(payload, findings):
    """The 1.1.21-1.1.24 report_hash, exactly as those releases computed it."""
    hashed = {k: payload[k] for k in LEGACY_HASHED_KEYS if k in payload}
    if isinstance(hashed.get("probes"), list):
        hashed["probes"] = sorted(str(p) for p in hashed["probes"])
    hashed["findings"] = sorted(({k: f[k] for k in LEGACY_FINDING_KEYS if k in f} for f in findings),
                                key=lambda d: json.dumps(d, sort_keys=True))
    return hashlib.sha256(json.dumps(hashed, sort_keys=True).encode()).hexdigest(), sorted(hashed)


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
EVIDENCE_SCHEME_V2 = "evidence-binding-v2"   # + ledger, ledger_head
EVIDENCE_SCHEME = "evidence-binding-v3"      # + prior_row: the head row itself, with its own signature
_ENTRY_KEYS = {
    EVIDENCE_SCHEME_V1: ["access_class", "state_id"],
    EVIDENCE_SCHEME_V2: ["access_class", "ledger", "ledger_head", "state_id"],
    EVIDENCE_SCHEME: ["access_class", "ledger", "ledger_head", "prior_row", "state_id"],
}
_ACCESS_CLASSES = ("anonymous", "authenticated")
_LEDGER_KEY = re.compile(r"^[A-Za-z0-9._-]+/(anonymous|authenticated)\.jsonl$")


def _hex64(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _check_prior_row(payload, entry):
    """prior_row must be exactly the row ledger_head names (or both null), and well formed.

    Its own attestation is checked against published keys by
    evidence.delta.delta_from_report / evidence.ledger.verify_row, not here:
    integrity and report-signature verification need no keys beyond the report's.
    """
    row, head = entry["prior_row"], entry["ledger_head"]
    if (row is None) != (head is None):
        raise ValueError("evidence.states prior_row must be present exactly when ledger_head is")
    if row is None:
        return
    from mcp_authscan.evidence.ledger import UNKNOWN_KEY, UNSIGNED, verify_row
    from mcp_authscan.evidence.state import normalize_target
    if not isinstance(row, dict) or row.get("state_id") != head:
        raise ValueError("evidence.states prior_row.state_id must equal ledger_head")
    header = {"schema": "boundary-ledger-v1", "target": normalize_target(payload.get("target", "")),
              "access_class": entry["access_class"]}
    if verify_row(header, row, []) not in (UNKNOWN_KEY, UNSIGNED):   # structure only; no keys here
        raise ValueError("evidence.states prior_row is malformed")


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
        if ev["scheme"] in (EVIDENCE_SCHEME_V2, EVIDENCE_SCHEME):
            ledger, head = entry["ledger"], entry["ledger_head"]
            if ledger is not None and (not isinstance(ledger, str) or not _LEDGER_KEY.match(ledger)
                                       or not ledger.endswith(f"/{entry['access_class']}.jsonl")):
                raise ValueError("evidence.states ledger must be null or <chain>/<access_class>.jsonl")
            if head is not None and not _hex64(head):
                raise ValueError("evidence.states ledger_head must be null or 64 lowercase hex")
            if ledger is None and head is not None:
                raise ValueError("evidence.states ledger_head requires a ledger")
        if ev["scheme"] == EVIDENCE_SCHEME:
            _check_prior_row(payload, entry)
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
    return verify_payload(payload)


def verify_payload(payload):
    """verify() on an already-parsed report, so a caller that read the bytes once (the verify
    MCP server) checks the hash and the signature of the same content."""
    if not isinstance(payload, dict):
        return "NOT_REPRODUCIBLE", "report is not a JSON object"
    if not payload.get("report_hash"):
        return "NOT_REPRODUCIBLE", "no report_hash in file"
    if is_legacy(payload):
        # Same checks and verdict strings as the 1.1.24 verifier.
        missing = [k for k in LEGACY_HASHED_KEYS if k not in payload]
        if missing:
            return "NOT_REPRODUCIBLE", "missing covered keys: " + ",".join(missing)
        # A distinct verdict, never plain MATCH: a 1.1.24 report must not read like a
        # schema-3 report, and nothing attests to it (the format was never signed).
        got, covered = compute_legacy(payload, payload.get("findings") or [])
        if got == payload["report_hash"]:
            return LEGACY_MATCH, got
        return LEGACY_MISMATCH, f"claimed {payload['report_hash']}, recomputed {got} over {len(covered)} covered fields"
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


def authenticity(payload, keys):
    """One word for the signature column: SIGNED BY <key_id>, SIGNATURE INVALID, UNKNOWN KEY,
    UNSIGNED, or SIGNATURE NOT CHECKED (no --keys given, or cryptography not installed)."""
    if is_legacy(payload):
        return "UNSIGNED (" + LEGACY_NOTE + ")"
    sig = payload.get("signature")
    if sig is None:
        return "UNSIGNED"
    if keys is None:
        return "SIGNATURE NOT CHECKED (pass --keys KEYS.json)"
    if not isinstance(sig, dict) or sorted(sig) != ["alg", "key_id", "value"] or sig.get("alg") != "ed25519":
        return "SIGNATURE INVALID"
    entry = next((k for k in keys if isinstance(k, dict) and k.get("key_id") == sig["key_id"]
                  and k.get("alg") == "ed25519"), None)
    if entry is None:
        return "UNKNOWN KEY"
    try:
        import base64

        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return "SIGNATURE NOT CHECKED (install mcp-authscan[signing])"
    try:
        content = signed_content(payload, payload.get("findings") or [])
        raw = base64.urlsafe_b64decode(entry["public_key"] + "=" * (-len(entry["public_key"]) % 4))
        value = base64.urlsafe_b64decode(sig["value"] + "=" * (-len(sig["value"]) % 4))
        Ed25519PublicKey.from_public_bytes(raw).verify(value, content)
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return "SIGNATURE INVALID"
    return "SIGNED BY " + sig["key_id"]


def _load_keys(path):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "keys" in data:
        data = data["keys"]
    return data if isinstance(data, list) else [data]


def main(argv=None):
    """python -m mcp_authscan.report_verify [--keys KEYS.json] REPORT.json [...]

    One line per report: integrity verdict, authenticity verdict, path, detail.
    Integrity is MATCH / MISMATCH for schema 3 and LEGACY MATCH / LEGACY MISMATCH
    for the 1.1.21-1.1.24 format, so the two can never print the same word.
    Exit 0 only if every integrity verdict is a match and no signature is
    invalid or from an unknown key.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    keys = None
    if args[:1] == ["--keys"]:
        if len(args) < 2:
            print("usage: python -m mcp_authscan.report_verify [--keys KEYS.json] REPORT.json [...]", file=sys.stderr)
            return 2
        keys = _load_keys(args[1])
        args = args[2:]
    if not args:
        print("usage: python -m mcp_authscan.report_verify [--keys KEYS.json] REPORT.json [...]", file=sys.stderr)
        return 2
    ok = True
    for path in args:
        try:
            status, detail = verify(path)
            with open(path, encoding="utf-8") as fh:
                auth = authenticity(json.load(fh), keys)
        except (OSError, ValueError) as e:
            status, detail, auth = "NOT_REPRODUCIBLE", f"{type(e).__name__}: {e}", "-"
        print(f"{status.replace('_', ' '):<16}  {auth:<40}  {path}  {detail}")
        ok = ok and status in ("MATCH", LEGACY_MATCH) and not auth.startswith(("SIGNATURE INVALID", "UNKNOWN KEY"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
