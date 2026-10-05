#!/usr/bin/env python3
"""External ground-truth probe for mcp-authscan. Runs the scanner against MCP/OAuth
auth advisories filed by OTHER researchers, pinned at their pre-fix commit. A CATCH =
the expected rule fired at the advisory's root-cause file ("A-class" = any detector).
NOT seeded from VATA findings - the honest test of whether detectors generalize.
Does not gate CI; it starts red and goes green as coverage improves."""
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "mcp_authscan.py"
MANIFEST = Path(__file__).resolve().parent / "external_advisories.json"
DETECTORS = {"A1", "A2", "A3", "A6", "A7", "A10"}

def run(cmd, **kw): return subprocess.run(cmd, capture_output=True, text=True, **kw)

def fetch_at(repo, sha, dest):
    dest.mkdir(parents=True, exist_ok=True)
    run(["git", "init", "-q"], cwd=dest); run(["git", "remote", "add", "origin", repo], cwd=dest)
    r = run(["git", "fetch", "-q", "--depth", "1", "origin", sha], cwd=dest)
    if r.returncode != 0:
        r = run(["git", "fetch", "-q", "origin", sha], cwd=dest)
        if r.returncode != 0: return False
    return run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest).returncode == 0

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--keep", action="store_true")
    ap.add_argument("--workdir", default=None); args = ap.parse_args()
    m = json.loads(MANIFEST.read_text())
    wd = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="authscan-ext-"))
    wd.mkdir(parents=True, exist_ok=True)
    caught = 0; rows = []
    for a in m["advisories"]:
        dest = wd / a["id"]
        if not fetch_at(a["repo"], a["prefix_commit"], dest):
            rows.append((a["id"], "FETCHFAIL")); print(f"[ERR] {a['id']}: fetch failed"); continue
        r = run([sys.executable, str(SCANNER), str(dest), "--json"])
        try: findings = json.loads(r.stdout)["findings"]
        except Exception: rows.append((a["id"], "SCANERR")); continue
        want, rcf = a["expected_rule"], a["root_cause_file"]
        hits = [f for f in findings if rcf in f.get("file", "")
                and (f["rule"] == want if want != "A-class" else f["rule"] in DETECTORS)]
        verdict = "CATCH" if hits else "MISS"; caught += 1 if hits else 0
        rows.append((a["id"], verdict))
        print(f"[{verdict:5}] {a['id']:24} ({a['reporter']}) expect {want} @ {rcf}")
        if hits: print(f"         {hits[0]['rule']} {hits[0]['file']}:{hits[0]['line']}")
    if not args.keep and not args.workdir: run(["rm", "-rf", str(wd)])
    print("\n" + "=" * 60)
    print(f"External ground truth: {caught}/{len(m['advisories'])} advisories caught at root cause")
    print("(Roadmap tracker; expected to start below 100%.)")
    for aid, v in rows: print(f"  {v:9} {aid}")
    return 0

if __name__ == "__main__": sys.exit(main())
