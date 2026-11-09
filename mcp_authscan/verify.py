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
import json
import os
import sys
import tempfile

from mcp_authscan.monolith import PROBE_SET_VERSION, main as scan_main
from mcp_authscan.report_verify import HASH_SCHEME, HASHED_KEYS, compute


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
    return names


def _refuse(reason):
    print("NOT_REPRODUCIBLE")
    print(reason)
    return 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("report", help="path to a saved JSON report")
    parser.add_argument(
        "--allow-private",
        action="store_true",
        help="forward --allow-private to the scanner (off by default)",
    )
    parser.add_argument("--authorized-by", help="forwarded to the scanner when given")
    parser.add_argument("--auth-basis", help="forwarded to the scanner when given")
    parser.add_argument("--contact", help="forwarded to the scanner when given")
    args = parser.parse_args(argv)
    try:
        payload = json.load(open(args.report, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _refuse("report file unreadable")
    if not isinstance(payload, dict):
        return _refuse("report file unreadable")
    if not payload.get("report_hash"):
        return _refuse("report_hash absent")
    missing = [key for key in HASHED_KEYS if key not in payload]
    if missing:
        return _refuse("missing covered keys: " + ",".join(missing))
    if payload.get("hash_scheme") != HASH_SCHEME:
        return _refuse(
            "report was produced with hash scheme %s, this is %s, install the recorded version to reproduce it"
            % (payload.get("hash_scheme"), HASH_SCHEME)
        )
    if payload.get("probe_set_version") != PROBE_SET_VERSION:
        return _refuse(
            "report was produced with %s, this is %s, install the recorded version to reproduce it"
            % (payload.get("probe_set_version"), PROBE_SET_VERSION)
        )
    target = payload.get("target")
    if not isinstance(target, str) or not target:
        return _refuse("target absent")
    fresh = _rerun(target, _scan_flags(payload, args))
    if fresh is None:
        return _refuse("rerun produced no report")
    original_digest = compute(payload, payload.get("findings") or [])[0]
    fresh_digest = compute(fresh, fresh.get("findings") or [])[0]
    if original_digest == fresh_digest:
        print("MATCH")
        return 0
    print("DIVERGENCE")
    print(",".join(_differing_fields(payload, fresh)))
    return 1


if __name__ == "__main__":
    sys.exit(main())
