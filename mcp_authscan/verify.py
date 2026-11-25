"""Verify a saved report offline; optionally reproduce it live.

Usage:
    python3 -m mcp_authscan.verify REPORT.json
    python3 -m mcp_authscan.verify --json REPORT.json
    python3 -m mcp_authscan.verify --keys KEYS.json REPORT.json
    python3 -m mcp_authscan.verify --reproduce [--allow-private] REPORT.json

Verification is decided by mcp_authscan.verification, the single verdict
engine also used by the web route and the report_verify adapters. Stages run
in a fixed order: catalog, format, integrity, authenticity. Signatures are
checked against the packaged, SHA-256-pinned key history unless --keys names
another trust anchor (a key-history-v1 file or a published keys.json); --keys
also requires a signature, as before. --require-signature does that with the
packaged anchor.

Line 1 is MATCH or LEGACY_MATCH (exit 0), NOT_REPRODUCIBLE when the catalog or
format stage fails (exit 2), INTEGRITY when the stored report_hash does not match
(exit 1), or AUTHENTICITY when the signature is rejected or required but absent
(exit 1). --json prints the engine's full result instead, with the same exit code.

--reproduce is a separate, explicitly requested network operation: after offline
verification passes, it reruns the same probe set in-process via
mcp_authscan.monolith.main and compares report_hash (DIVERGENCE on drift).
--allow-private is forwarded only when passed here; --authorized-by, --auth-basis
and --contact come from this command or from the report's authorization object.
Output never contains payload values, tokens or credentials.
"""
import argparse
import json
import os
import sys
import tempfile

from mcp_authscan.monolith import PROBE_SET_VERSION, main as scan_main
from mcp_authscan.report_verify import HASHED_KEYS, compute


def _rerun(target, extra_args):
    """Call monolith.main in-process and return its payload dict, or None."""
    handle, path = tempfile.mkstemp(suffix=".json")
    os.close(handle)
    argv = ["mcp_authscan", "--json", "-o", path]
    argv.extend(extra_args)
    argv.append(target)
    old_argv = sys.argv
    old_out, old_err = sys.stdout, sys.stderr
    devnull_out = open(os.devnull, "w")
    devnull_err = open(os.devnull, "w")
    try:
        sys.argv = argv
        sys.stdout = devnull_out
        sys.stderr = devnull_err
        try:
            scan_main()
        except SystemExit:
            pass
        if not os.path.exists(path) or os.path.getsize(path) == 0:
            return None
        try:
            payload = json.load(open(path, encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict):
            return None
        return payload
    finally:
        sys.argv = old_argv
        sys.stdout = old_out
        sys.stderr = old_err
        devnull_out.close()
        devnull_err.close()
        try:
            os.unlink(path)
        except OSError:
            pass


def _scan_flags(payload, args):
    extra = []
    if args.allow_private:
        extra.append("--allow-private")
    auth = payload.get("authorization") if isinstance(payload.get("authorization"), dict) else {}
    authorized_by = args.authorized_by or auth.get("authorized_by")
    auth_basis = args.auth_basis or auth.get("basis")
    contact = args.contact or auth.get("contact")
    if authorized_by:
        extra.extend(["--authorized-by", authorized_by])
    if auth_basis:
        extra.extend(["--auth-basis", auth_basis])
    if contact:
        extra.extend(["--contact", contact])
    fail_on = payload.get("fail_on")
    if fail_on in ("critical", "high", "medium"):
        extra.extend(["--fail-on", fail_on])
    scope = payload.get("scope")
    if isinstance(scope, str) and scope:
        extra.extend(["--scope", scope])
    return extra


def _differing_fields(original, fresh):
    # Name HASHED_KEYS whose payload values differ. Findings are not in that
    # tuple; detect them by calling compute() twice on the original payload
    # with each findings list so the projection stays inside compute().
    names = [key for key in HASHED_KEYS if original.get(key) != fresh.get(key)]
    original_hash = compute(original, original.get("findings") or [])[0]
    swapped = compute(original, fresh.get("findings") or [])[0]
    if original_hash != swapped:
        names.append("findings")
    if original.get("hash_scheme") == "verdict-v4" and "probes" in fresh:
        if compute({**original, "probes": fresh["probes"]}, original.get("findings") or [])[0] != original_hash:
            names.append("probes")
    if original.get("report_hash") != original_hash:
        names.append("report_hash")
    return names


def _refuse(reason):
    print("NOT_REPRODUCIBLE")
    print(reason)
    return 2




from mcp_authscan import verification  # noqa: E402

# Re-exported: the pin lives with the engine.
CATALOG_SHA256 = verification.CATALOG_SHA256


def _catalog_path():
    return verification.catalog_path()


def _lines(result):
    auth, probes = result["authenticity"], result["probe_statuses"]
    key = " " + auth["key_id"] if auth.get("verdict") == "SIGNED BY" and auth.get("key_id") else ""
    anchor = result["trust_anchor"]
    return [
        "CATALOG_SHA256=" + str(result["catalog"].get("sha256")),
        "PROBE_SET_ATTESTATION=" + str(result["catalog"].get("attestation")),
        "REPORT_HASH=" + str(result["integrity"].get("report_hash")),
        "HASH_SCHEME=" + str(result["integrity"].get("hash_scheme")),
        "EVIDENCE_HASH=" + str(result["integrity"].get("evidence_hash")),
        "EVIDENCE_HASH_SCHEME=" + str(result["integrity"].get("evidence_hash_scheme")),
        "AUTHENTICITY=" + auth["verdict"] + key,
        "PROBE_STATUSES=" + probes["verdict"] + ("" if probes["verdict"] == "VERIFIED" else " (" + probes["reason"] + ")"),
        "TRUST_ANCHOR=" + "%s:%s" % (anchor.get("source"), anchor.get("sha256")),
    ]


def main(argv=None):
    """Offline verification by default; live reproduction requires --reproduce."""
    parser = argparse.ArgumentParser(description="Verify a saved report offline")
    parser.add_argument("report")
    parser.add_argument("--keys", help="Trust anchor: key-history-v1 file or published keys.json (requires a signature)")
    parser.add_argument("--require-signature", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print the engine's full result as JSON")
    parser.add_argument("--reproduce", action="store_true")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--authorized-by")
    parser.add_argument("--auth-basis")
    parser.add_argument("--contact")
    args = parser.parse_args(argv)

    try:
        with open(args.report, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        return _refuse("%s: %s" % (type(exc).__name__, exc))
    anchor = "packaged"
    if args.keys:
        try:
            anchor = verification.external_anchor(args.keys)
        except verification.AnchorError as exc:
            return _refuse("key verification failed: %s" % exc)
    result = verification.verify(raw, anchor=anchor, catalog_file=_catalog_path())
    require = bool(args.keys or args.require_signature)
    stage = result["failed_stage"]
    if stage is None and require and result["authenticity"]["verdict"] != "SIGNED BY":
        stage = "authenticity"

    if stage in ("catalog", "format"):
        code, head = 2, ["NOT_REPRODUCIBLE", result[stage]["reason"]]
    elif stage == "integrity":
        code, head = 1, ["INTEGRITY", "report_hash"]
    elif stage == "authenticity":
        code, head = 1, ["AUTHENTICITY", result["authenticity"]["verdict"] + ": " + result["authenticity"]["reason"]]
    else:
        code = 0
        head = ["LEGACY_MATCH" if result["format"]["verdict"] == "LEGACY" else "MATCH"]

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return code
    if code != 0 or not args.reproduce:
        print("\n".join(head + ([] if stage in ("catalog", "format") else _lines(result))))
        return code

    # Explicitly requested network operation, separate from verification.
    payload = json.loads(raw)
    stamp = payload.get("probe_set_version")
    if stamp != PROBE_SET_VERSION:
        return _refuse(
            "live reproduction requires execution logic for %s; "
            "installed runner is %s" % (stamp, PROBE_SET_VERSION)
        )

    target = payload.get("target")
    if not isinstance(target, str) or not target:
        return _refuse("target absent")

    fresh = _rerun(target, _scan_flags(payload, args))
    if fresh is None:
        return _refuse("rerun produced no report")

    try:
        new_hash = compute(fresh, fresh.get("findings") or [])[0]
    except (ValueError, TypeError):
        return _refuse("invalid rerun report")

    if new_hash != payload["report_hash"]:
        print("DIVERGENCE")
        print(",".join(_differing_fields(payload, fresh)))
        return 1

    print("MATCH")
    return 0


if __name__ == "__main__":
    sys.exit(main())
