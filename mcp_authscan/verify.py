"""Reproduce a saved report by re-running the same probe set on the same target.

Usage:
    python3 -m mcp_authscan.verify path/to/report.json
    python3 -m mcp_authscan.verify --allow-private path/to/report.json
    python3 -m mcp_authscan.verify --authorized-by NAME --auth-basis BASIS \
        --contact EMAIL path/to/report.json

This is not a scanner of its own. It reads target, probe_set_version and
report_hash from the saved file, then calls mcp_authscan.monolith.main
in-process (the function that builds the graded JSON payload). No new
probes are added. The payload dict is taken from the JSON that main()
writes to a private tempfile via --json -o; stdout is discarded. There
is no separate builder that returns the dict, and this tool does not
reimplement hashing or the HASHED_KEYS structure.

--allow-private is off by default and is forwarded only when passed
here. The scanner also requires --authorized-by, --auth-basis and
--contact; supply them on this command, or they are taken from a
report authorization object when present. --fail-on and --scope are
taken from the report when present so those graded fields stay aligned
with the original run. No other flags are invented or forwarded.

Prints MATCH, DIVERGENCE or NOT_REPRODUCIBLE on line 1. Divergence
lists differing HASHED_KEYS names (and findings when compute() says
they differ). Never prints payload values, tokens or credentials,
except the recorded and local probe_set_version or hash_scheme in the
two NOT_REPRODUCIBLE messages that name those versions.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile

from mcp_authscan.monolith import PROBE_SET_VERSION, main as scan_main
from mcp_authscan.report_verify import HASH_SCHEME, HASHED_KEYS, compute
from mcp_authscan import report_verify


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
    if original.get("report_hash") != original_hash:
        names.append("report_hash")
    return names


def _refuse(reason):
    print("NOT_REPRODUCIBLE")
    print(reason)
    return 2




# Immutable expected digest. Never derive this value from the loaded catalog
# at verification time.
CATALOG_SHA256 = "f055f8b91ba8b7a5f46afee32a2769d0740bb153a85b5aacfbc38f3485f4bd92"


def _catalog_path():
    from pathlib import Path
    return Path(__file__).with_name("probe_set_catalog.json")


def _load_catalog():
    raw = _catalog_path().read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != CATALOG_SHA256:
        raise ValueError("catalog digest mismatch")
    catalog = json.loads(raw)
    if catalog.get("schema") != "probe-set-catalog-v1":
        raise ValueError("unsupported catalog schema")
    if not isinstance(catalog.get("stamps"), dict):
        raise ValueError("catalog stamps missing")
    return catalog, actual


def main(argv=None):
    """Offline verification by default; live reproduction requires --reproduce."""
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Verify a saved report offline")
    parser.add_argument("report")
    parser.add_argument("--keys", help="Published trusted keys JSON")
    parser.add_argument("--reproduce", action="store_true")
    parser.add_argument("--allow-private", action="store_true")
    parser.add_argument("--authorized-by")
    parser.add_argument("--auth-basis")
    parser.add_argument("--contact")
    args = parser.parse_args(argv)

    try:
        with open(args.report, encoding="utf-8") as fh:
            payload = json.load(fh)
        if not isinstance(payload, dict):
            return _refuse("report must be an object")

        catalog, catalog_digest = _load_catalog()
        stamp = payload.get("probe_set_version")

        from mcp_authscan.releases import PROBE_SET_RELEASES
        known = set(catalog["stamps"]) | set(PROBE_SET_RELEASES)
        if stamp not in known:
            return _refuse("unknown probe set: %s" % stamp)

        status, detail = report_verify.verify(args.report)

    except (OSError, ValueError, TypeError, KeyError) as exc:
        return _refuse("%s: %s" % (type(exc).__name__, exc))

    if status not in ("MATCH", "LEGACY_MATCH"):
        if status in ("MISMATCH", "LEGACY_MISMATCH"):
            print("INTEGRITY")
            print("report_hash")
            return 1
        return _refuse(str(detail))

    if args.keys:
        try:
            keys = report_verify._load_keys(args.keys)
            authenticity = report_verify.authenticity(payload, keys)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            return _refuse("key verification failed: %s" % exc)
        if not authenticity.startswith("SIGNED BY "):
            print("SIGNATURE_INVALID")
            print(authenticity)
            return 1

    if not args.reproduce:
        print(status)
        print("CATALOG_SHA256=" + catalog_digest)
        print("REPORT_HASH=" + str(payload["report_hash"]))
        return 0

    # Explicitly requested network operation, separate from verification.
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
