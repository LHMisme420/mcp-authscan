"""Offline, stdin-only adapter around the CLI's canonical report hash."""
import json
import re
import sys

from .report_verify import HASH_SCHEME, SCHEMA_VERSION, compute


def verify_text(text):
    algorithm = None
    probe_set = None

    def result(verdict, reason):
        return dict(verdict=verdict, reason=reason, algorithm=algorithm,
                    probe_set_version=probe_set)

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
        scheme = payload.get("hash_scheme")
        algorithm = "SHA-256 / " + scheme if isinstance(scheme, str) else None
        probe_set = payload.get("probe_set_version")
        if not isinstance(probe_set, str):
            probe_set = None
        if scheme != HASH_SCHEME or payload.get("schema_version") != SCHEMA_VERSION:
            return result("UNREADABLE", "Only verdict-v3 schema version 3 is supported; legacy hashes are not reinterpreted.")
        claimed = payload.pop("report_hash", None)
        if not isinstance(claimed, str) or not re.fullmatch(r"[0-9a-f]{64}", claimed):
            return result("UNREADABLE", "A complete lowercase SHA-256 report_hash is required.")
        findings = payload.get("findings")
        if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
            return result("UNREADABLE", "The report must contain a complete findings array.")
        if probe_set is None:
            return result("UNREADABLE", "A declared probe_set_version string is required.")
        actual, _ = compute(payload, findings)
        if actual == claimed:
            return result("INTACT", "Graded content matches the stored hash; this does not authenticate the report's author.")
        return result("ALTERED", "Graded content does not match the stored hash; a hash cannot identify which field changed.")
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        # Do not echo user-controlled report content, including parsing errors.
        return result("UNREADABLE", "Invalid JSON or incomplete/inconsistent schema-3 graded content.")


if __name__ == "__main__":
    print(json.dumps(verify_text(sys.stdin.read()), ensure_ascii=True, allow_nan=False))
