"""Description study runner over the October combined audit's target list.

    python tools/description_study.py [--out PATH] [--workers N]

Takes no target file argument. The source is the combined audit json in the
mcp-security-registry data directory (MCPAUTHSCAN_STUDY_SOURCE overrides the path, for
tests). Only the keys of its `findings` dict are read: each key is host plus path. No
severity, verdict or other column from the source is read or carried over.

Each key is normalised to https://host/path and duplicates collapse. Every host is
resolved before probing; a host that will not resolve goes into `skipped` with reason
dns, is excluded from coverage and is never graded. The description probe then runs on
the resolved targets and one study entry is written.
"""
import argparse
import hashlib
import json
import os
import socket
import sys
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_SOURCE = Path.home() / "vata" / "mcp-security-registry" / "data" / "combined_vata_audit.json"
STATEMENT = ("The target list is the October combined audit (combined_vata_audit.json, "
             "findings keys only). It is not the 16,072 registry walk.")
ROWS_SCHEME = "verdict-v4"
EVIDENCE_SCHEME = "probe-evidence-v1"


def source_path():
    return Path(os.environ.get("MCPAUTHSCAN_STUDY_SOURCE") or DEFAULT_SOURCE)


def normalise(key):
    """host plus path -> https://host/path. None if no host."""
    key = key.strip()
    parts = urlsplit(key if "://" in key else "https://" + key)
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        return None
    netloc = host if parts.port in (None, 443) else "%s:%d" % (host, parts.port)
    path = parts.path.rstrip("/") or "/"
    return "https://%s%s" % (netloc, path)


def targets_from(keys):
    """Normalised, duplicates collapsed, sorted. Also the keys that had no host."""
    out, bad = set(), []
    for k in keys:
        t = normalise(k) if isinstance(k, str) else None
        if t:
            out.add(t)
        else:
            bad.append(k)
    return sorted(out), bad


def default_resolver(host):
    try:
        return bool(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
    except (socket.gaierror, UnicodeError, OSError):
        return False


def default_prober(target):
    from mcp_authscan import content_probe, description_probe
    try:
        cobs = content_probe.observe(target)
    except Exception as exc:  # egress refusal or transport failure: graded as EXCLUDED
        return description_probe.grade(None, target, reason="probe error: %s" % type(exc).__name__)
    reason = next((r for r in (cobs.get("reasons") or [])
                   if r.startswith("tools/list") or r.startswith("session not established")), None)
    return description_probe.grade(cobs.get("tools_items"), target, reason=reason,
                                   prompts=cobs.get("prompts_items"),
                                   resources=cobs.get("resources_items"))


def _ser(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def rows_hash(results):
    from mcp_authscan.report_verify import probe_rows
    body = [{"target": r["target"], "rows": probe_rows(r["rows"])} for r in results]
    return hashlib.sha256(_ser({"scheme": ROWS_SCHEME, "targets": sorted(body, key=_ser)})).hexdigest()


def evidence_hash(results):
    from mcp_authscan.report_verify import evidence_hash as per_target
    body = [{"target": r["target"], "evidence_hash": per_target(r["rows"])} for r in results]
    return hashlib.sha256(_ser({"scheme": EVIDENCE_SCHEME, "targets": sorted(body, key=_ser)})).hexdigest()


def tool_version():
    return metadata.version("mcp-authscan")


def probe_set_version():
    from mcp_authscan.monolith import PROBE_SET_VERSION
    return PROBE_SET_VERSION


def build_entry(raw, *, resolver=default_resolver, prober=default_prober, workers=16,
                version=None, probe_set=None, now=None, study_id=None):
    data = json.loads(raw)
    keys = list(data["findings"].keys())  # keys only; values never read
    targets, bad = targets_from(keys)
    skipped = [{"key": k, "reason": "unparseable"} for k in bad]
    resolved = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        hosts = list(ex.map(lambda t: resolver(urlsplit(t).hostname), targets))
    for t, ok in zip(targets, hosts):
        (resolved.append(t) if ok else skipped.append({"target": t, "reason": "dns"}))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        graded = list(ex.map(prober, resolved))
    results = [{"target": t, "rows": rows} for t, rows in zip(resolved, graded)]
    reasons = {}
    for s in skipped:
        reasons[s["reason"]] = reasons.get(s["reason"], 0) + 1
    return {
        "study_id": study_id or "desc-study-" + uuid.uuid4().hex[:12],
        "statement": STATEMENT,
        "source_file": "combined_vata_audit.json",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "key_count": len(keys),
        "target_count": len(targets),
        "resolved_count": len(resolved),
        "skipped_count": len(skipped),
        "skipped_reasons": reasons,
        "skipped": skipped,
        "tool_version": version or tool_version(),
        "probe_set_version": probe_set or probe_set_version(),
        "run_timestamp": now or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rows_hash_scheme": ROWS_SCHEME,
        "rows_hash": rows_hash(results),
        "evidence_hash_scheme": EVIDENCE_SCHEME,
        "evidence_hash": evidence_hash(results),
        "targets": results,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", default="description_study.json")
    ap.add_argument("--workers", type=int, default=16)
    a = ap.parse_args(argv)
    src = source_path()
    if not src.is_file():
        print("missing source: %s" % src, file=sys.stderr)
        return 2
    import mcp_authscan
    print("mcp-authscan package version: %s (%s)" % (tool_version(), mcp_authscan.__file__))
    entry = build_entry(src.read_bytes(), workers=a.workers)
    Path(a.out).write_text(json.dumps(entry, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    flagged = sum(1 for r in entry["targets"] for row in r["rows"] if row.get("status") == "FLAGGED")
    print("study %s: keys=%d targets=%d resolved=%d skipped=%d %s flagged_rows=%d"
          % (entry["study_id"], entry["key_count"], entry["target_count"], entry["resolved_count"],
             entry["skipped_count"], entry["skipped_reasons"], flagged))
    print("source_sha256=%s\nrows_hash=%s\nevidence_hash=%s\nwrote %s"
          % (entry["source_sha256"], entry["rows_hash"], entry["evidence_hash"], a.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
