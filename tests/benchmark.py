#!/usr/bin/env python3
"""
Precision / recall / F1 benchmark for mcp-authscan.

Unlike verify_ground_truth.py (regression: "do seeds still fire?"), this scores
the detectors against the full VATA labeled corpus - known-vuln AND human-cleared
repos - at pinned commit SHAs, so numbers are reproducible and survive patching.

Detector rules carry precision claims. Review-list rules (A4/A5/B2, MEDIUM B1)
enumerate surface and are NEVER counted as FPs.
  positive: expected detector fires = TP; missing = FN.
  negative: any detector hit = FP; none = TN.
  latent:   detector hit in tolerate set = flagged not FP; else FP.
  coverage gaps: listed, not scored (acknowledged out-of-rule-scope).
Precision=TP/(TP+FP)  Recall=TP/(TP+FN)  F1=harmonic mean.
Emits report_sha256 you can anchor. Exit 1 if recall<floor or any FP.

Usage:
    python3 tests/benchmark.py
    python3 tests/benchmark.py --only lucky-aeon,webrix,1mcp-agent
    python3 tests/benchmark.py --json report.json --keep
"""
import argparse, hashlib, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "mcp_authscan.py"
MANIFEST = Path(__file__).resolve().parent / "benchmark_manifest.json"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def fetch_at(repo, sha, dest):
    dest.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q"], cwd=dest)
    run(["git", "remote", "add", "origin", repo], cwd=dest)
    r = run(["git", "fetch", "-q", "--depth", "1", "origin", sha], cwd=dest)
    if r.returncode != 0:
        r = run(["git", "fetch", "-q", "origin", sha], cwd=dest)
        if r.returncode != 0:
            return False, (r.stderr or "fetch failed").strip().splitlines()[-1:]
    co = run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest)
    return co.returncode == 0, ""


def scan(path):
    r = run([sys.executable, str(SCANNER), str(path), "--json"])
    try:
        return json.loads(r.stdout)
    except Exception:
        return {"findings": [], "_scan_error": (r.stderr or r.stdout)[:300]}


def is_detector(f, detector_rules, b1_conf):
    rule = f.get("rule", "")
    if rule == "B1":
        return f.get("confidence", "").upper() == b1_conf
    return rule in detector_rules


def detector_rules_fired(findings, detector_rules, b1_conf):
    out = {}
    for f in findings:
        if is_detector(f, detector_rules, b1_conf):
            out.setdefault(f["rule"], []).append(f'{f.get("file","?")}:{f.get("line","?")}')
    return out


def main():
    ap = argparse.ArgumentParser(description="P/R/F1 benchmark for mcp-authscan")
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--only", default=None, help="comma-separated case names")
    ap.add_argument("--json", dest="json_out", default=None, help="write anchorable report")
    args = ap.parse_args()

    if not SCANNER.exists():
        print(f"ERROR: scanner not found at {SCANNER}"); return 1
    m = json.loads(MANIFEST.read_text())
    detector_rules = set(m["detector_rules"])
    b1_conf = m.get("b1_detector_confidence", "HIGH").upper()
    recall_floor = m.get("recall_floor", 0.0)
    only = set(args.only.split(",")) if args.only else None

    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="mcp-authscan-bench-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"workdir: {workdir}\n")

    TP = FP = FN = TN = 0
    rows, review_hits, flags, errors = [], [], [], []
    want = lambda n: only is None or n in only

    for c in m["positives"]:
        if not want(c["name"]): continue
        dest = workdir / c["name"]
        ok, err = fetch_at(c["repo"], c["commit"], dest)
        if not ok: errors.append((c["name"], err)); print(f"[ERR]  {c['name']}: fetch {err}"); continue
        res = scan(dest)
        if "_scan_error" in res: errors.append((c["name"], res["_scan_error"])); print(f"[ERR]  {c['name']}: {res['_scan_error']}"); continue
        fired = detector_rules_fired(res["findings"], detector_rules, b1_conf)
        all_rules = {f.get("rule") for f in res["findings"]}
        print(f"[pos]  {c['name']}  ({c['commit'][:10]})  detectors: {sorted(fired) or 'none'}")
        for rule in c.get("expect_detect", []):
            if rule in fired: TP += 1; print(f"  TP   {rule}  {fired[rule][0]}")
            else: FN += 1; print(f"  FN   {rule}  <- expected detector did NOT fire")
        for rule in c.get("expect_review", []):
            present = rule in all_rules
            review_hits.append((c["name"], rule, "fired" if present else "absent"))
            print(f"  rev  {rule}  {'present' if present else 'absent'} (review-list, unscored)")
        rows.append({"case": c["name"], "label": "positive", "commit": c["commit"], "detector_fired": fired, "expected": c.get("expect_detect", [])})

    for c in m["negatives"]:
        if not want(c["name"]): continue
        dest = workdir / c["name"]
        ok, err = fetch_at(c["repo"], c["commit"], dest)
        if not ok: errors.append((c["name"], err)); print(f"[ERR]  {c['name']}: fetch {err}"); continue
        res = scan(dest)
        if "_scan_error" in res: errors.append((c["name"], res["_scan_error"])); print(f"[ERR]  {c['name']}: {res['_scan_error']}"); continue
        fired = detector_rules_fired(res["findings"], detector_rules, b1_conf)
        print(f"[neg]  {c['name']}  ({c['commit'][:10]})  detectors: {sorted(fired) or 'none'}")
        if fired:
            for rule, locs in fired.items(): FP += 1; print(f"  FP   {rule}  {locs[0]}  <- detector fired on CLEAN repo")
        else: TN += 1; print(f"  TN   clean")
        rows.append({"case": c["name"], "label": "negative", "commit": c["commit"], "detector_fired": fired})

    for c in m.get("latent", []):
        if not want(c["name"]): continue
        dest = workdir / c["name"]
        ok, err = fetch_at(c["repo"], c["commit"], dest)
        if not ok: errors.append((c["name"], err)); print(f"[ERR]  {c['name']}: fetch {err}"); continue
        res = scan(dest)
        if "_scan_error" in res: errors.append((c["name"], res["_scan_error"])); print(f"[ERR]  {c['name']}: {res['_scan_error']}"); continue
        fired = detector_rules_fired(res["findings"], detector_rules, b1_conf)
        tol = set(c.get("tolerate_detect", []))
        print(f"[lat]  {c['name']}  ({c['commit'][:10]})  detectors: {sorted(fired) or 'none'}")
        for rule in fired:
            if rule in tol: flags.append((c["name"], rule, "tolerated-latent")); print(f"  FLAG {rule}  tolerated (pattern present, unreachable)")
            else: FP += 1; print(f"  FP   {rule}  {fired[rule][0]}  <- unexpected detector on latent repo")
        rows.append({"case": c["name"], "label": "latent", "commit": c["commit"], "detector_fired": fired, "tolerate": sorted(tol)})

    precision = TP / (TP + FP) if (TP + FP) else 1.0
    recall = TP / (TP + FN) if (TP + FN) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print("\n" + "=" * 64)
    print(f"Detector confusion:  TP={TP}  FP={FP}  FN={FN}  TN={TN}")
    print(f"Precision={precision:.3f}  Recall={recall:.3f}  F1={f1:.3f}")
    if flags:
        print(f"\nTolerated latent hits (precision ceiling, not FP): {len(flags)}")
        for n, r, _ in flags: print(f"  {n}  {r}")
    gaps = [g for g in m.get("coverage_gaps", []) if want(g["name"])]
    if gaps:
        print(f"\nKnown coverage gaps (confirmed findings, no current rule) -> roadmap: {len(gaps)}")
        for g in gaps: print(f"  {g['name']}: {g.get('candidate_rule','(TBD)')}")
    if errors:
        print(f"\nErrors: {len(errors)}")
        for n, e in errors: print(f"  {n}: {e}")

    report = {"tool": "mcp-authscan benchmark", "detector_rules": sorted(detector_rules),
              "confusion": {"TP": TP, "FP": FP, "FN": FN, "TN": TN},
              "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
              "cases": rows,
              "review_list_hits": [{"case": n, "rule": r, "status": s} for n, r, s in review_hits],
              "tolerated_latent": [{"case": n, "rule": r} for n, r, _ in flags],
              "coverage_gaps": [g["name"] for g in gaps],
              "errors": [{"case": n, "detail": e} for n, e in errors]}
    report["report_sha256"] = hashlib.sha256(json.dumps(report, sort_keys=True).encode()).hexdigest()
    print(f"\nreport_sha256: {report['report_sha256']}  (anchor this)")
    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2)); print(f"wrote {args.json_out}")

    if not args.keep and not args.workdir: run(["rm", "-rf", str(workdir)])
    failed = (recall < recall_floor) or (FP > 0) or bool(errors)
    print("\nRESULT:", "FAIL" if failed else "PASS", f"(recall floor {recall_floor}, FP must be 0)")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
