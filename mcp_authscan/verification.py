"""The single verdict engine for saved mcp-authscan reports.

Every verifier front end calls ``verify()``: the CLI (``mcp_authscan.verify``),
the web route (``mcp_authscan.verify_upload`` behind server/reportVerification.ts),
and the ``report_verify.verify`` / ``report_verify.authenticity`` adapters used by
the policy gate, ``report_verify.main`` and verify-mcp. None of them decides a
verdict of its own.

The engine is offline and deterministic: it opens no socket, reads no clock and
no environment variable, and reads only the two packaged data files whose
SHA-256 digests are pinned below (or a trust anchor file the caller names).

Stages run in a fixed order:

1. catalog       the packaged probe-set catalog must match CATALOG_SHA256.
2. format        strict JSON, a supported report format, a declared probe set that the
                 catalog, releases.py or the web-source digest form names (the result
                 says which: only IN CATALOG is attested by the pinned catalog), and
                 complete graded content.
3. integrity     the recomputed report_hash against the stored one.
4. authenticity  the signature, checked against a pinned key history.

A catalog or format failure stops evaluation: later stages report NOT CHECKED.
Integrity and authenticity are both evaluated once the format is readable,
because a signature covers the canonical graded content, not the stored
report_hash; neither answer is derived from the other. ``failed_stage`` names
the first failing stage in the fixed order.

What a valid signature proves depends on its sig_version. Probe statuses are
outside report_hash; only a verified sig_version 3, 4 or 5 signature covers them.
For every other report ``probe_statuses`` is NOT VERIFIED, also when an older
signature form verifies.
"""
import base64
import hashlib
import json
import re
from pathlib import Path

from mcp_authscan import report_verify as rv

ENGINE = "mcp-authscan-verify/1"
STAGES = ("catalog", "format", "integrity", "authenticity")

# Immutable expected digests. Never derive either value from the loaded file.
CATALOG_SHA256 = "f055f8b91ba8b7a5f46afee32a2769d0740bb153a85b5aacfbc38f3485f4bd92"
KEY_HISTORY_SHA256 = "d2b99e9713f749956dc087a8a19f08611b43f8e93de22dd1427a0898d62f54b7"

NOT_CHECKED = "NOT CHECKED"
_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
# app.py stamps web-app reports with a digest of the web check engine's source: a
# different engine from the CLI probe sets the catalog describes.
_WEB_SOURCE = re.compile(r"^web-source-sha256:[0-9a-f]{64}$")
ATTESTATION = {
    "catalog": "IN CATALOG",
    "releases": "RELEASES ONLY (releases.py names it; the pinned catalog has no entry)",
    "web-source": "WEB SOURCE DIGEST (web check engine, not a CLI probe set; the catalog does not describe it)",
}
_KEY_STATUSES = ("active", "withdrawn", "revoked")

# What each signature form's bytes cover (report_verify.signed_content).
COVERS = {
    rv.SIG_VERSION_GRADED: ("graded report",),
    rv.SIG_VERSION_EVIDENCE: ("graded report", "evidence"),
    rv.SIG_VERSION_PROVENANCE: ("graded report", "evidence", "probes", "provenance"),
    rv.SIG_VERSION_OPERATIONS: ("graded report", "evidence", "probes", "provenance",
                                "content_observed.operations"),
    # Form 5 signs content_observed.operations when present (null otherwise); verify()
    # reports operations NOT VERIFIED for a form-5 report that declares none.
    rv.SIG_VERSION_DEPLOYMENT: ("graded report", "evidence", "probes", "provenance",
                                "content_observed.operations", "deployment_acknowledgment"),
}
# Authenticity verdicts that fail the stage. NOT SIGNED and NOT CHECKED do not:
# they mean authenticity was not established, not that it was contradicted.
AUTHENTICITY_FAILURES = ("SIGNATURE INVALID", "UNKNOWN KEY", "KEY NOT VALID", "DIVERGENCE",
                         "UNSUPPORTED FORM", "UNREADABLE", "UNAVAILABLE")


class AnchorError(ValueError):
    """The trust anchor is missing, fails its pin, or is malformed."""


def catalog_path():
    return Path(__file__).with_name("probe_set_catalog.json")


def key_history_path():
    return Path(__file__).with_name("key_history.json")


def _b64url_bytes(value, size):
    if not isinstance(value, str) or not _B64URL.fullmatch(value):
        return None
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError:
        return None
    if len(raw) != size or base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        return None
    return raw


def _strict_json(text):
    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON object key")
            value[key] = item
        return value

    def no_constants(_name):
        raise ValueError("non-finite JSON number")

    return json.loads(text, object_pairs_hook=unique_object, parse_constant=no_constants)


def _load_catalog(path):
    raw = Path(path).read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != CATALOG_SHA256:
        raise ValueError("catalog digest mismatch")
    catalog = _strict_json(raw.decode("utf-8"))
    if not isinstance(catalog, dict) or catalog.get("schema") != "probe-set-catalog-v1":
        raise ValueError("unsupported catalog schema")
    if not isinstance(catalog.get("stamps"), dict):
        raise ValueError("catalog stamps missing")
    return catalog, actual


def _anchor_entries(document, *, history):
    """Validated key entries. A plain key list (published keys.json form) is all active."""
    if history:
        if not isinstance(document, dict) or document.get("schema") != "key-history-v1":
            raise AnchorError("key history must use schema key-history-v1")
        entries = document.get("keys")
    else:
        entries = document.get("keys") if isinstance(document, dict) else document
    if not isinstance(entries, list):
        raise AnchorError("trust anchor must list keys")
    seen, out = set(), []
    for entry in entries:
        if not isinstance(entry, dict):
            raise AnchorError("trust anchor key entries must be objects")
        key_id, public_key = entry.get("key_id"), entry.get("public_key")
        status = entry.get("status", "active") if history else "active"
        if (not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id) or key_id in seen
                or entry.get("alg") != "ed25519" or _b64url_bytes(public_key, 32) is None
                or status not in _KEY_STATUSES):
            raise AnchorError("trust anchor key entry is malformed")
        seen.add(key_id)
        withdrawn = entry.get("withdrawn") if history else None
        out.append({"key_id": key_id, "alg": "ed25519", "public_key": public_key, "status": status,
                    "withdrawn_commit": (withdrawn or {}).get("commit") if isinstance(withdrawn, dict) else None})
    return out


def packaged_anchor(path=None):
    """The pinned key history shipped with the package; raises AnchorError if it fails its pin."""
    try:
        raw = Path(path or key_history_path()).read_bytes()
    except OSError:
        raise AnchorError("packaged key history is unavailable") from None
    digest = hashlib.sha256(raw).hexdigest()
    if digest != KEY_HISTORY_SHA256:
        raise AnchorError("packaged key history digest mismatch")
    try:
        document = _strict_json(raw.decode("utf-8"))
    except ValueError:
        raise AnchorError("packaged key history is not valid JSON") from None
    return {"source": "packaged", "sha256": digest, "keys": _anchor_entries(document, history=True)}


def external_anchor(path):
    """A caller-named trust anchor: a key-history-v1 file or a published keys.json list.

    Its digest is reported, never pinned: choosing it is the caller's trust decision.
    """
    try:
        raw = Path(path).read_bytes()
        document = _strict_json(raw.decode("utf-8"))
    except (OSError, ValueError):
        raise AnchorError("trust anchor file is unavailable or not valid JSON") from None
    history = isinstance(document, dict) and document.get("schema") == "key-history-v1"
    return {"source": "external", "sha256": hashlib.sha256(raw).hexdigest(),
            "keys": _anchor_entries(document, history=history)}


def anchor_from_keys(keys):
    """Adapter for callers that already hold a parsed key list (policy gate, verify-mcp)."""
    if isinstance(keys, dict) and "keys" in keys:
        keys = keys["keys"]
    if isinstance(keys, dict):
        keys = [keys]
    return {"source": "caller", "sha256": None, "keys": _anchor_entries(keys, history=False)}


def published_keys(anchor):
    """The keys.json view of an anchor: active keys only, in the published shape."""
    return {"keys": [{"key_id": k["key_id"], "alg": k["alg"], "public_key": k["public_key"]}
                     for k in anchor["keys"] if k["status"] == "active"]}


def _stamp_kind(stamp, catalog):
    """catalog, releases, web-source, or None when nothing names this probe set."""
    from mcp_authscan.releases import PROBE_SET_RELEASES
    if stamp in catalog["stamps"]:
        return "catalog"
    if stamp in PROBE_SET_RELEASES:
        return "releases"
    if _WEB_SOURCE.fullmatch(stamp):
        return "web-source"
    return None


def _not_checked(reason):
    return {"verdict": NOT_CHECKED, "reason": reason}


def _coverage(verdict, sig_version):
    """Which signed components a verdict establishes. Nothing is VERIFIED unless SIGNED BY."""
    covers = COVERS.get(sig_version, ()) if verdict == "SIGNED BY" else ()

    def component(name, needs):
        if name in covers:
            return {"verdict": "VERIFIED", "reason": f"Covered by a verified sig_version {sig_version} signature."}
        if verdict != "SIGNED BY":
            return {"verdict": "NOT VERIFIED", "reason": f"No verified signature covers {name}."}
        return {"verdict": "NOT VERIFIED",
                "reason": f"sig_version {sig_version} does not cover {name}; {needs}."}

    return covers, {
        "probe_statuses": component("probes", "only sig_version 3 or later covers probe statuses"),
        "operations": component("content_observed.operations", "only sig_version 4 or 5 covers operations"),
        "evidence": component("evidence", "sig_version 2 or later covers evidence"),
        "provenance": component("provenance", "sig_version 3 or later covers provenance"),
        "deployment_acknowledgment": component("deployment_acknowledgment",
                                               "only sig_version 5 covers deployment_acknowledgment"),
    }


def _authenticity(payload, findings, legacy, integrity_verdict, anchor, anchor_error):
    sig_version = None if legacy else payload.get(rv.SIG_VERSION_KEY, rv.SIG_VERSION_GRADED)

    def result(verdict, reason, key_id=None):
        return {"verdict": verdict, "reason": reason, "key_id": key_id, "sig_version": sig_version}

    if legacy:
        if "signature" in payload:
            return result("UNREADABLE", "The pre-schema-3 format (releases 1.1.21-1.1.24) was never signed; "
                                        "its signature field cannot be evaluated.")
        return result("NOT SIGNED", "The pre-schema-3 format (releases 1.1.21-1.1.24) was never signed.")
    if "signature" not in payload:
        return result("NOT SIGNED", "No signature field is present.")
    if isinstance(sig_version, bool) or sig_version not in rv.SIG_VERSIONS:
        return result("UNSUPPORTED FORM", f"sig_version {sig_version!r} is not a form this verifier knows; "
                                          "an unknown form is unsupported, never treated as forged.")
    sig = payload["signature"]
    key_id = sig.get("key_id") if isinstance(sig, dict) and isinstance(sig.get("key_id"), str) \
        and _KEY_ID.fullmatch(sig.get("key_id")) else None
    if (not isinstance(sig, dict) or key_id is None or sig.get("alg") != "ed25519"
            or sorted(sig) != ["alg", "key_id", "value"]):
        return result("UNREADABLE", "Signature must contain exactly ed25519 alg, a short key_id and a base64url value.", key_id)
    detached = _b64url_bytes(sig.get("value"), 64)
    if detached is None:
        return result("UNREADABLE", "Signature value must encode exactly 64 bytes as unpadded base64url.", key_id)
    if anchor_error is not None:
        return result("UNAVAILABLE", f"Trust anchor unavailable: {anchor_error}.", key_id)
    if anchor is None:
        return result(NOT_CHECKED, "No trust anchor was supplied.", key_id)
    entry = next((k for k in anchor["keys"] if k["key_id"] == key_id), None)
    if entry is None:
        return result("UNKNOWN KEY", f"This key_id is not in the {anchor['source']} trust anchor.", key_id)
    try:
        content = rv.signed_content(payload, findings)
    except (ValueError, TypeError, KeyError) as error:
        message = str(error)
        component = ("sig_version" if message.startswith("sig_version") else
                     "evidence" if message.startswith("evidence") else
                     "content_observed" if message.startswith("content_observed") else
                     "deployment_acknowledgment" if message.startswith("deployment_acknowledgment") else
                     "provenance")
        return result("DIVERGENCE", f"Signed-content component differs or cannot be reconstructed: {component}.", key_id)
    if entry["status"] != "active":
        where = f" in commit {entry['withdrawn_commit']}" if entry.get("withdrawn_commit") else ""
        return result("KEY NOT VALID", f"Key {entry['status']}{where}. Reports carry no signed signing time, so no "
                                       "signature by this key can be shown to predate that; every signature by it "
                                       "is rejected.", key_id)
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return result("UNAVAILABLE", "Ed25519 verification needs the cryptography package.", key_id)
    try:
        Ed25519PublicKey.from_public_bytes(_b64url_bytes(entry["public_key"], 32)).verify(detached, content)
    except InvalidSignature:
        covered = ", ".join(COVERS[sig_version])
        if integrity_verdict == "INTACT":
            outside = [c for c in COVERS[sig_version] if c != "graded report"]
            where = " / ".join(outside) if outside else "the signature value only"
            reason = (f"Signature does not verify over the sig_version {sig_version} signed content ({covered}). "
                      f"report_hash is intact, so graded content is unchanged; the change is in {where}, "
                      "or in the signature value.")
        else:
            reason = (f"Signature does not verify over the sig_version {sig_version} signed content ({covered}). "
                      "Graded content also differs from the stored report_hash.")
        return result("SIGNATURE INVALID", reason, key_id)
    return result("SIGNED BY", f"Ed25519 signature verifies over the sig_version {sig_version} signed content "
                               f"({', '.join(COVERS[sig_version])}).", key_id)


def verify(text, *, anchor="packaged", catalog_file=None, key_history_file=None):
    """Verify one saved report. Returns a JSON-serializable dict; never raises for report content.

    ``text`` is the report as str or UTF-8 bytes. ``anchor`` is "packaged" (the pinned key
    history), None (do not check signatures), or a dict from external_anchor/anchor_from_keys.
    """
    out = {"engine": ENGINE, "stages": list(STAGES), "failed_stage": None}
    anchor_error = None
    if anchor == "packaged":
        try:
            anchor = packaged_anchor(key_history_file)
        except AnchorError as error:
            anchor, anchor_error = None, str(error)
    out["trust_anchor"] = ({"source": anchor["source"], "sha256": anchor["sha256"]} if anchor
                           else {"source": None, "sha256": None, "error": anchor_error})

    def stop(stage, **sections):
        out["failed_stage"] = stage
        for name in STAGES:
            if name not in out:
                out[name] = sections.get(name) or _not_checked(f"Not evaluated: the {stage} stage failed.")
        out.update(_coverage(None, None)[1])
        return out

    # 1. catalog
    try:
        catalog, digest = _load_catalog(catalog_file or catalog_path())
    except (OSError, ValueError, UnicodeDecodeError) as error:
        out["catalog"] = {"verdict": "FAILED", "reason": f"{type(error).__name__}: {error}",
                          "sha256_expected": CATALOG_SHA256}
        return stop("catalog")
    out["catalog"] = {"verdict": "PINNED", "sha256": digest, "stamp_in_catalog": None, "attestation": None}

    # 2. format
    fmt = {"verdict": "UNREADABLE", "algorithm": None, "probe_set_version": None, "form": None}

    def bad(reason, verdict="UNREADABLE"):
        fmt.update(verdict=verdict, reason=reason)
        out["format"] = fmt
        return stop("format")

    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        payload = _strict_json(text)
    except (ValueError, UnicodeDecodeError, RecursionError):
        # Never echo user-controlled content, including parser messages.
        return bad("Invalid JSON: not UTF-8, malformed, duplicate keys or a non-finite number.")
    if not isinstance(payload, dict):
        return bad("The report must be a JSON object.")
    scheme = payload.get("hash_scheme")
    legacy = rv.is_legacy(payload)
    if not legacy and (scheme not in rv.HASH_SCHEMES or payload.get("schema_version") != rv.SCHEMA_VERSION):
        return bad("Only verdict-v3 or verdict-v4 schema version 3 and the pre-schema-3 format of releases "
                   "1.1.21-1.1.24 are supported; other hashes are not reinterpreted.")
    fmt["hash_scheme"] = scheme
    fmt["algorithm"] = "SHA-256 / " + scheme + (" (" + rv.LEGACY_NOTE + ")" if legacy else "")
    fmt["form"] = "legacy-1.1.21-1.1.24" if legacy else "schema-3"
    stamp = payload.get("probe_set_version")
    if not isinstance(stamp, str) or not stamp:
        return bad("A declared probe_set_version string is required.")
    fmt["probe_set_version"] = stamp
    kind = _stamp_kind(stamp, catalog)
    out["catalog"]["stamp_in_catalog"] = kind == "catalog"
    out["catalog"]["attestation"] = ATTESTATION.get(kind, "UNKNOWN")
    if kind is None:
        return bad("Declared probe set is not in the pinned catalog or releases.py and is not a web source "
                   "digest.", "UNKNOWN PROBE SET")
    findings = payload.get("findings")
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        return bad("The report must contain a complete findings array.")
    claimed = payload.get("report_hash")
    if not isinstance(claimed, str) or not _HEX64.fullmatch(claimed):
        return bad("A complete lowercase SHA-256 report_hash is required.")
    graded = {k: v for k, v in payload.items() if k != "report_hash"}
    try:
        if legacy:
            missing = [k for k in rv.LEGACY_HASHED_KEYS if k not in payload]
            if missing:
                return bad("A pre-schema-3 report must contain every field its hash covers.")
            actual, covered = rv.compute_legacy(graded, findings)
        else:
            actual, covered = rv.compute(graded, findings)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        return bad("Incomplete or inconsistent graded content (missing fields, truncated findings or "
                   "severity counts that do not match the findings).")
    fmt.update(verdict="LEGACY" if legacy else "SCHEMA 3", reason=f"Readable {fmt['form']} report.")
    out["format"] = fmt

    # 2b. probe-evidence-v1, required with verdict-v4 and absent before it
    ev_scheme = ev_claimed = ev_actual = None
    if scheme == rv.HASH_SCHEME_V4 and not legacy:
        ev_scheme, ev_claimed = payload.get("evidence_hash_scheme"), payload.get("evidence_hash")
        if ev_scheme != rv.EVIDENCE_HASH_SCHEME or not isinstance(ev_claimed, str) or not _HEX64.fullmatch(ev_claimed):
            return bad("A verdict-v4 report requires evidence_hash_scheme " + rv.EVIDENCE_HASH_SCHEME
                       + " and a complete lowercase SHA-256 evidence_hash.")
        try:
            ev_actual = rv.evidence_hash(payload["probes"])
        except (ValueError, TypeError, KeyError):
            return bad("Incomplete probe rows for probe-evidence-v1.")
    out["format"] = fmt

    # 3. integrity
    ev_intact = ev_actual == ev_claimed
    intact = actual == claimed and ev_intact
    out["integrity"] = {
        "verdict": "INTACT" if intact else "ALTERED",
        "reason": ("Graded content matches the stored hash; this does not authenticate the report's author."
                   if intact else
                   "Graded content does not match the stored hash; a hash cannot identify which field changed.")
        + (" Probe rows (id, name, status, http status, body digest, prerequisite met, limitation, severity) are "
           "inside this verdict-v4 hash; observed headers, excerpts and content_observed are outside it."
           if scheme == rv.HASH_SCHEME_V4 else
           " Probe statuses and content_observed are outside this hash; only a verified signature covers them."
           if not legacy else
           " LEGACY: pre-schema-3 report (releases " + ", ".join(rv.LEGACY_RELEASES) + "), checked with that"
           " format's own pre-1.1.25 algorithm; unsigned, nothing attests to it."),
        "report_hash": claimed, "recomputed": actual, "covered_fields": len(covered),
        "hash_scheme": scheme, "graded_verdict": "INTACT" if actual == claimed else "ALTERED",
        "evidence_hash_scheme": ev_scheme, "evidence_hash": ev_claimed, "evidence_recomputed": ev_actual,
        "evidence_verdict": None if ev_scheme is None else ("INTACT" if ev_intact else "ALTERED"),
    }

    # 4. authenticity
    auth = _authenticity(payload, findings, legacy, out["integrity"]["verdict"], anchor, anchor_error)
    covers, components = _coverage(auth["verdict"], auth["sig_version"])
    auth["covers"] = list(covers)
    out["authenticity"] = auth
    if auth["sig_version"] == rv.SIG_VERSION_DEPLOYMENT and components["operations"]["verdict"] == "VERIFIED":
        try:
            declared = rv.operations_binding(payload) is not None
        except ValueError:
            declared = False
        if not declared:
            components["operations"] = {"verdict": "NOT VERIFIED",
                                        "reason": "This sig_version 5 report declares no content_observed.operations."}
    out.update(components)
    if not intact:
        out["failed_stage"] = "integrity"
    elif auth["verdict"] in AUTHENTICITY_FAILURES:
        out["failed_stage"] = "authenticity"
    return out


def passed(result, *, require_signature=False):
    """True when no stage failed and, if required, a signature verified."""
    if result["failed_stage"] is not None:
        return False
    return not require_signature or result["authenticity"]["verdict"] == "SIGNED BY"
