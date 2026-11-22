"""Offline, stdin-only adapter around the CLI's canonical report hash."""
import base64
import json
import re
import sys

from .report_verify import (
    HASH_SCHEME,
    LEGACY_HASHED_KEYS,
    LEGACY_RELEASES,
    SCHEMA_VERSION,
    compute,
    compute_legacy,
    is_legacy,
    signed_content,
)


def _legacy_result(payload, result):
    """A 1.1.21-1.1.24 report, verified with that format's own algorithm (report_verify.compute_legacy).

    Integrity only: the format was never signed, so canonical_bytes stays None
    and authenticity can never read as signed.
    """
    claimed = payload.get("report_hash")
    findings = payload.get("findings")
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        return result("UNREADABLE", "The report must contain a complete findings array.")
    if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed):
        return result("UNREADABLE", "A complete lowercase SHA-256 report_hash is required.")
    if any(k not in payload for k in LEGACY_HASHED_KEYS):
        return result("UNREADABLE", "A pre-schema-3 report must contain every field its hash covers.")
    actual, _ = compute_legacy(payload, findings)
    note = (" LEGACY: pre-schema-3 report (releases " + ", ".join(LEGACY_RELEASES) + "), checked with that"
            " format's own pre-1.1.25 algorithm; unsigned, nothing attests to it.")
    if actual == claimed:
        return result("INTACT", "Graded content matches the stored hash; this does not authenticate the report's author." + note)
    return result("ALTERED", "Graded content does not match the stored hash; a hash cannot identify which field changed." + note)


def verify_text(text):
    algorithm = None
    probe_set = None
    signature_present = None
    signature = None
    canonical_bytes = None
    sig_version = None
    divergence = None

    def result(verdict, reason):
        return dict(verdict=verdict, reason=reason, algorithm=algorithm,
                    probe_set_version=probe_set, signature_present=signature_present,
                    signature=signature, canonical_bytes=canonical_bytes,
                    sig_version=sig_version, divergence=divergence)

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON object key")
            value[key] = item
        return value

    try:
        payload = json.loads(text, object_pairs_hook=unique_object,
                             parse_constant=lambda _: (_ for _ in ()).throw(
                                 ValueError("Non-finite JSON number")))
        if not isinstance(payload, dict):
            return result("UNREADABLE", "The report must be a JSON object.")
        signature_present = "signature" in payload
        signature = payload.get("signature")
        sig_version = payload.get("sig_version", 1)
        scheme = payload.get("hash_scheme")
        algorithm = "SHA-256 / " + scheme if isinstance(scheme, str) else None
        probe_set = payload.get("probe_set_version")
        if not isinstance(probe_set, str):
            probe_set = None
        if is_legacy(payload):
            return _legacy_result(payload, result)
        if scheme != HASH_SCHEME or payload.get("schema_version") != SCHEMA_VERSION:
            return result("UNREADABLE", "Only verdict-v3 schema version 3 is supported; legacy hashes are not reinterpreted.")
        claimed = payload.pop("report_hash", None)
        findings = payload.get("findings")
        if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
            return result("UNREADABLE", "The report must contain a complete findings array.")
        if probe_set is None:
            return result("UNREADABLE", "A declared probe_set_version string is required.")
        actual, _ = compute(payload, findings)
        # Use the CLI's serializer/projection, not a second implementation in JS.
        # This internal transport is never returned to the browser or persisted.
        try:
            canonical_bytes = base64.b64encode(signed_content(payload, findings)).decode("ascii")
        except (ValueError, TypeError, KeyError) as error:
            # Name only a component demonstrated by structural validation.
            message = str(error)
            component = ("sig_version" if message.startswith("sig_version") else
                          "evidence" if message.startswith("evidence") else
                          "content_observed" if message.startswith("content_observed") else "provenance")
            divergence = component
        if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed):
            return result("UNREADABLE", "A complete lowercase SHA-256 report_hash is required.")
        if actual == claimed:
            return result("INTACT", "Graded content matches the stored hash; this does not authenticate the report's author. Probe statuses and content_observed are outside this hash; only a verified signature covers them.")
        divergence = divergence or "report"
        return result("ALTERED", "Graded content does not match the stored hash; a hash cannot identify which field changed.")
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        # Do not echo user-controlled report content, including parsing errors.
        return result("UNREADABLE", "Invalid JSON or incomplete/inconsistent schema-3 graded content.")


if __name__ == "__main__":
    print(json.dumps(verify_text(sys.stdin.read()), ensure_ascii=True, allow_nan=False))
