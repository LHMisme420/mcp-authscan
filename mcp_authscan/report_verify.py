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


# verdict-v4: verdict-v3 plus one row per probe. Same schema_version 3 report
# shape; only the hash preimage differs. The scheme name is inside the preimage
# so a v3 and a v4 hash can never be taken over the same bytes. Volatile probe
# fields (body_sha256, headers_observed, body_excerpt, detail, endpoint, timings,
# request ids) stay out: only the graded meaning of each row is committed to.
# body_sha256 is committed to separately, by evidence_hash below.
HASH_SCHEME_V4 = "verdict-v4"
HASH_SCHEMES = (HASH_SCHEME, HASH_SCHEME_V4)
PROBE_ROW_KEYS = (
    "probe_id", "name", "status", "http_status",
    "prerequisite_met", "limitation", "severity",
)
# Graded scheme order for the gate's min-graded-scheme. The 1.1.21-1.1.24 legacy
# format also says verdict-v3 but ranks below it (see graded_scheme_rank).
GRADED_SCHEME_RANK = {"verdict-v3": 3, "verdict-v4": 4}

# probe-evidence-v1: a second hash, separate from report_hash, over one body
# digest per probe row. Response bodies can carry server-varying bytes, so this
# value is not expected to repeat across scans; the graded hash is.
EVIDENCE_HASH_SCHEME = "probe-evidence-v1"
EVIDENCE_ROW_KEYS = ("probe_id", "name", "body_sha256")


def graded_scheme_rank(payload):
    if is_legacy(payload):
        return 2
    return GRADED_SCHEME_RANK.get(payload.get("hash_scheme"), 0)


def evidence_hash(probes):
    """(hex, preimage keys) for probe-evidence-v1 over the probes array."""
    if not isinstance(probes, list) or any(not isinstance(p, dict) for p in probes):
        raise ValueError("probe-evidence-v1 requires a probes array of objects")
    rows = []
    for probe in probes:
        missing = [k for k in EVIDENCE_ROW_KEYS if k not in probe]
        if missing:
            raise ValueError("probe-evidence-v1 row missing: " + ",".join(missing))
        rows.append({k: probe[k] for k in EVIDENCE_ROW_KEYS})
    content = serialize({"scheme": EVIDENCE_HASH_SCHEME, "rows": sorted(rows, key=serialize)})
    return hashlib.sha256(content).hexdigest()


def probe_rows(probes):
    """The verdict-v4 projection of the probes array, order-independent, duplicates kept."""
    if not isinstance(probes, list) or any(not isinstance(p, dict) for p in probes):
        raise ValueError("verdict-v4 requires a probes array of objects")
    rows = []
    for probe in probes:
        missing = [k for k in PROBE_ROW_KEYS if k not in probe]
        if missing:
            raise ValueError("verdict-v4 probe row missing: " + ",".join(missing))
        rows.append({k: probe[k] for k in PROBE_ROW_KEYS})
    return sorted(rows, key=serialize)


def _check_description_rows(probes):
    """A FLAGGED description row's offset and quoted substring are hashed inside its name; the
    displayed fields must agree with that name, or the report does not verify."""
    for p in probes:
        if p.get("probe_class") != "description" or p.get("status") != "FLAGGED":
            continue
        want = "@%s:%s" % (p.get("offset"), json.dumps(p.get("substring"), ensure_ascii=True))
        if not str(p.get("name", "")).endswith(want):
            raise ValueError("description row fields disagree with its hashed name: %r" % (p.get("name"),))


def canonical_report(payload, findings):
    scheme = payload.get("hash_scheme", HASH_SCHEME)
    if scheme not in HASH_SCHEMES:
        raise ValueError("Unknown hash_scheme: %r" % (scheme,))
    missing = [key for key in HASHED_KEYS if key not in payload]
    if scheme == HASH_SCHEME_V4 and "probes" not in payload:
        missing.append("probes")
    if missing:
        raise ValueError("Missing schema-3 fields: " + ",".join(missing))
    result = {key: payload[key] for key in HASHED_KEYS}
    if scheme == HASH_SCHEME_V4:
        result["hash_scheme"] = scheme
        result["probes"] = probe_rows(payload["probes"])
        _check_description_rows(payload["probes"])
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


PROVENANCE_KEY = "provenance"
PROVENANCE_KEYS = ("tool_version", "tool_manifest")


def provenance_binding(payload):
    """Validated provenance binding, or None when the report carries none.

    tool_version names the package that produced the report. tool_manifest is the
    sha256 over that package's own source bytes. Both sit outside report_hash,
    which covers graded content only, and inside the signature.
    """
    if PROVENANCE_KEY not in payload:
        return None
    prov = payload[PROVENANCE_KEY]
    if (not isinstance(prov, dict) or sorted(prov) != sorted(PROVENANCE_KEYS)
            or not all(isinstance(prov[k], str) and prov[k] for k in PROVENANCE_KEYS)
            or not _hex64(prov["tool_manifest"])):
        raise ValueError("provenance must be tool_version and tool_manifest, manifest 64 lowercase hex")
    return prov


def pin_status(payload):
    """Locally computed, never signed: does this manifest match a pinned release?"""
    prov = provenance_binding(payload)
    if not prov:
        return "NO PROVENANCE"
    from mcp_authscan.releases import MANIFEST_HASHES
    pin = MANIFEST_HASHES.get(prov["tool_version"])
    if not pin:
        return "VERSION NOT PINNED"
    if pin == prov["tool_manifest"]:
        return "MANIFEST MATCHES PIN"
    return "MANIFEST NOT PINNED"


SIG_VERSION_KEY = "sig_version"
SIG_VERSION_GRADED = 1     # signed bytes: canonical graded report (the report_hash preimage)
SIG_VERSION_EVIDENCE = 2   # signed bytes: canonical {"sig_version": 2, "evidence": ..., "report": ...}
SIG_VERSION_PROVENANCE = 3
SIG_VERSION_OPERATIONS = 4  # adds content_observed (with its operations list) to the form-3 bytes
SIG_VERSION_DEPLOYMENT = 5  # form-4 bytes (operations optional) plus deployment_acknowledgment
SIG_VERSIONS = (SIG_VERSION_GRADED, SIG_VERSION_EVIDENCE, SIG_VERSION_PROVENANCE, SIG_VERSION_OPERATIONS,
                SIG_VERSION_DEPLOYMENT)
CONTENT_KEY = "content_observed"
DEPLOYMENT_KEY = "deployment_acknowledgment"
OPERATIONS = ("initialize", "tools/list", "prompts/list", "resources/list")


def operations_binding(payload):
    """content_observed when it declares operations, validated; None when it does not.

    An operation is listed only if it succeeded: initialize when the MCP session was
    established, each */list when its result list was parsed. Signed at sig_version 4
    and 5 (the whole content_observed object, authentication_assurance included);
    outside report_hash.
    """
    co = payload.get(CONTENT_KEY)
    if not isinstance(co, dict) or "operations" not in co:
        return None
    if "credential_context" in co:
        if co["credential_context"] not in (
            "anonymous", "credentialed", "unknown"
        ):
            raise ValueError(
                "content_observed.credential_context: invalid value"
            )
    ops, est = co["operations"], co.get("session_established")
    if not isinstance(ops, list) or not all(isinstance(o, str) for o in ops) or len(set(ops)) != len(ops):
        raise ValueError("content_observed.operations must be a list of distinct strings")
    unknown = [o for o in ops if o not in OPERATIONS]
    if unknown:
        raise ValueError("content_observed.operations: unknown " + ", ".join(unknown))
    if not isinstance(est, bool):
        raise ValueError("content_observed.session_established must be true or false")
    if ("initialize" in ops) != est:
        raise ValueError("content_observed: initialize is listed exactly when session_established is true")
    return co


def deployment_binding(payload):
    """The structurally validated deployment_acknowledgment record, or None when absent.

    Signed only at sig_version 5; outside report_hash. Semantic checks (challenge id,
    nonce equality, response digest, result recomputation) live in deployment_ack.
    """
    if DEPLOYMENT_KEY not in payload:
        return None
    from mcp_authscan.deployment_ack import record_structure
    return record_structure(payload[DEPLOYMENT_KEY])


def sig_version_for(payload):
    """The sig_version a new signature over ``payload`` must declare."""
    if DEPLOYMENT_KEY in payload:
        return SIG_VERSION_DEPLOYMENT
    if PROVENANCE_KEY in payload:
        return SIG_VERSION_OPERATIONS if operations_binding(payload) is not None else SIG_VERSION_PROVENANCE
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
    if version != SIG_VERSION_DEPLOYMENT and DEPLOYMENT_KEY in payload:
        raise ValueError("sig_version: %d does not cover deployment_acknowledgment; it requires sig_version 5"
                         % version)
    if version == SIG_VERSION_GRADED:
        if ev is not None:
            raise ValueError("sig_version: 1 does not cover an evidence field; evidence requires sig_version 2")
        return serialize(canonical)
    if ev is None:
        raise ValueError("sig_version: %d requires an evidence field" % version)
    if version == SIG_VERSION_EVIDENCE:
        if PROVENANCE_KEY in payload:
            raise ValueError("sig_version: 2 does not cover a provenance field")
        return serialize({SIG_VERSION_KEY: version, EVIDENCE_KEY: ev, "report": canonical})
    prov = provenance_binding(payload)
    if prov is None:
        raise ValueError("sig_version: %d requires a provenance field" % version)
    ops = operations_binding(payload)
    body = {SIG_VERSION_KEY: version, EVIDENCE_KEY: ev, "report": canonical, "probes": payload.get("probes") or [], PROVENANCE_KEY: prov}
    if version == SIG_VERSION_PROVENANCE:
        if ops is not None:
            raise ValueError("sig_version: 3 does not cover content_observed.operations; operations require sig_version 4")
        return serialize(body)
    if version == SIG_VERSION_DEPLOYMENT:
        dap = deployment_binding(payload)
        if dap is None:
            raise ValueError("sig_version: 5 requires a deployment_acknowledgment field")
        # Form 5 signs content_observed (null when it declares no operations), so any
        # other content_observed, such as an authentication_assurance block without
        # operations, would sit outside the signature: refuse it instead.
        if ops is None and payload.get(CONTENT_KEY) not in (None, {}):
            raise ValueError("content_observed: sig_version 5 covers content_observed only when it "
                             "declares operations")
        body[CONTENT_KEY] = ops
        body[DEPLOYMENT_KEY] = dap
        return serialize(body)
    if ops is None:
        raise ValueError("sig_version: 4 requires content_observed.operations")
    body[CONTENT_KEY] = ops
    return serialize(body)


def verify(path):
    """Integrity verdict for a report file, decided by mcp_authscan.verification.

    Kept for its callers (policy gate, report_verify.main, verify-mcp). Returns
    MATCH / MISMATCH (schema 3), LEGACY_MATCH / LEGACY_MISMATCH (1.1.21-1.1.24),
    or NOT_REPRODUCIBLE when the catalog or format stage fails.
    """
    from mcp_authscan import verification
    with open(path, "rb") as source:
        result = verification.verify(source.read(), anchor=None)
    stage = result["failed_stage"]
    if stage in ("catalog", "format"):
        return "NOT_REPRODUCIBLE", result[stage]["reason"]
    integrity = result["integrity"]
    legacy = result["format"]["verdict"] == "LEGACY"
    if integrity["verdict"] == "INTACT":
        return (LEGACY_MATCH if legacy else "MATCH"), integrity["recomputed"]
    return (LEGACY_MISMATCH if legacy else "MISMATCH"), "claimed %s, recomputed %s over %d covered fields" % (
        integrity["report_hash"], integrity["recomputed"], integrity["covered_fields"])


def authenticity(payload, keys):
    """One word for the signature column, decided by mcp_authscan.verification.

    SIGNED BY <key_id>, SIGNATURE INVALID, UNKNOWN KEY, KEY NOT VALID, UNSIGNED,
    UNSUPPORTED FORM, or SIGNATURE NOT CHECKED (no keys given, or cryptography not
    installed). ``keys`` is the caller's key list (its trust decision); None skips
    the signature check.
    """
    from mcp_authscan import verification
    try:
        text = json.dumps(payload, allow_nan=False)
    except (TypeError, ValueError):
        return "SIGNATURE INVALID"
    try:
        anchor = None if keys is None else verification.anchor_from_keys(keys)
    except verification.AnchorError:
        return "SIGNATURE NOT CHECKED (keys are malformed)"
    result = verification.verify(text, anchor=anchor)
    auth = result["authenticity"]
    verdict = auth["verdict"]
    if result["failed_stage"] in ("catalog", "format"):
        stage = result["failed_stage"]
        return f"SIGNATURE NOT CHECKED (report {stage}: {result[stage]['reason']})"
    if verdict == "NOT SIGNED":
        return "UNSIGNED (" + LEGACY_NOTE + ")" if result["format"]["verdict"] == "LEGACY" else "UNSIGNED"
    if verdict == "UNSUPPORTED FORM":
        return f"UNSUPPORTED FORM (sig_version {auth['sig_version']!r})"
    if verdict == verification.NOT_CHECKED:
        return "SIGNATURE NOT CHECKED (pass --keys KEYS.json)"
    if verdict == "UNAVAILABLE":
        return "SIGNATURE NOT CHECKED (install mcp-authscan[signing])"
    if verdict == "SIGNED BY":
        return "SIGNED BY " + auth["key_id"]
    if verdict in ("UNKNOWN KEY", "KEY NOT VALID"):
        return verdict
    # SIGNATURE INVALID, DIVERGENCE (signed content cannot be rebuilt), UNREADABLE (malformed signature).
    return "SIGNATURE INVALID"


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
                doc = json.load(fh)
            auth = authenticity(doc, keys)
            pin = pin_status(doc)
            # Probe and operation labels come from the engine's verdict, never from a second rule here.
            from mcp_authscan import verification
            engine = verification.verify(json.dumps(doc), anchor=None if keys is None else verification.anchor_from_keys(keys))
            probes = ("signed" if engine["probe_statuses"]["verdict"] == "VERIFIED"
                      else "NOT VERIFIED (outside report_hash; needs sig_version 3 checked with --keys)")
            operations = ("signed" if engine["operations"]["verdict"] == "VERIFIED"
                          else "NOT VERIFIED (needs sig_version 4, or 5 with operations, checked with --keys)")
            if engine["format"].get("hash_scheme") == HASH_SCHEME_V4 and engine["probe_statuses"]["verdict"] != "VERIFIED":
                probes = "in report_hash (verdict-v4); signature NOT VERIFIED"
            report_ok = verification.passed(engine, require_signature=True)
            integ = engine["integrity"]
            scheme = "%s=%s evidence %s=%s" % (integ.get("hash_scheme") or "-", integ.get("report_hash") or "-",
                                               integ.get("evidence_hash_scheme") or "-", integ.get("evidence_hash") or "-")
        except (OSError, ValueError) as e:
            scheme = "-"
            status, detail, auth = "NOT_REPRODUCIBLE", f"{type(e).__name__}: {e}", "-"
            pin = "-"
            probes = "-"
            operations = "-"
            report_ok = False
        print(f"{status.replace('_', ' '):<16}  {auth:<40}  {path}  {detail}  [provenance: {pin}]  [probes: {probes}]  [operations: {operations}]  [scheme: {scheme}]")
        ok = ok and report_ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())



def build_provenance():
    """Provenance block for a report produced by this installation."""
    import hashlib
    import importlib.metadata
    dist = importlib.metadata.distribution("mcp-authscan")
    d = hashlib.sha256()
    for f in sorted(dist.files or [], key=str):
        if str(f).endswith(".py"):
            d.update(str(f).encode("utf-8"))
            d.update(b"::")
            d.update(dist.locate_file(f).read_bytes())
            d.update(b"::")
    return {"tool_version": __import__('mcp_authscan').__version__, "tool_manifest": d.hexdigest()}
