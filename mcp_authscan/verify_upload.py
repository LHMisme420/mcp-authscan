"""Offline, stdin-only adapter for the web route: prints mcp_authscan.verification's result.

server/reportVerification.ts spawns ``python3 -m mcp_authscan.verify_upload`` and
writes the uploaded report to stdin. This module prints the engine's verdict JSON
(catalog, format, integrity, authenticity, probe_statuses, ...) and decides nothing
itself; the route only shapes that JSON for the browser. Signatures are checked
against the packaged, SHA-256-pinned key history.
"""
import base64
import json
import sys

from mcp_authscan import verification
from mcp_authscan.report_verify import signed_content


def verify_text(text):
    """Compatibility view for existing callers: the engine's integrity verdict in the
    pre-engine shape (verdict INTACT / ALTERED / UNREADABLE).

    ``canonical_bytes`` is the exact signed content (report_verify.signed_content) for a
    schema-3 report, or None. It is a serializer output for tests and tools; no verdict
    is computed from it here and the web route does not use it.
    """
    result = verification.verify(text, anchor=None)
    stage = result["failed_stage"]
    fmt = result["format"]
    readable = stage not in ("catalog", "format")
    payload = None
    try:
        payload = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        pass
    if not isinstance(payload, dict):
        payload = None
    canonical_bytes = None
    divergence = None
    if readable and fmt["verdict"] == "SCHEMA 3":
        try:
            canonical_bytes = base64.b64encode(signed_content(payload, payload["findings"])).decode("ascii")
        except (ValueError, TypeError, KeyError) as error:
            message = str(error)
            divergence = ("sig_version" if message.startswith("sig_version") else
                          "evidence" if message.startswith("evidence") else
                          "content_observed" if message.startswith("content_observed") else "provenance")
    if readable and result["integrity"]["verdict"] == "ALTERED":
        divergence = divergence or "report"
    verdict = result["integrity"]["verdict"] if readable else "UNREADABLE"
    reason = result["integrity"]["reason"] if readable else result[stage]["reason"]
    return dict(
        verdict=verdict, reason=reason,
        algorithm=fmt.get("algorithm") if readable else None,
        probe_set_version=fmt.get("probe_set_version"),
        signature_present=("signature" in payload) if payload is not None else None,
        signature=payload.get("signature") if payload is not None else None,
        canonical_bytes=canonical_bytes,
        sig_version=payload.get("sig_version", 1) if payload is not None else None,
        divergence=divergence,
    )


if __name__ == "__main__":
    print(json.dumps(verification.verify(sys.stdin.buffer.read()), ensure_ascii=True, allow_nan=False))
