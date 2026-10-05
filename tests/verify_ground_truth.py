#!/usr/bin/env python3
"""
Reproducibility harness for mcp-authscan.

Clones the seed repositories listed in tests/ground_truth.json, runs the scanner
against each, and confirms every seed finding is still detected. This lets anyone
verify the tool's ground-truth claims without trusting the author: clone, run,
see the same findings.

Usage:
    python3 tests/verify_ground_truth.py            # clone (shallow) + scan + check
    python3 tests/verify_ground_truth.py --workdir /tmp/gt   # custom clone dir

Exit code 0 if every seed finding is re-detected, 1 otherwise (CI-friendly).
Requires: git, python3. No third-party packages.
"""
import argparse, json, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "mcp_authscan.py"
MANIFEST = Path(__file__).resolve().parent / "ground_truth.json"

def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)

def main():
    ap = argparse.ArgumentParser(description="Verify mcp-authscan re-detects its seed findings")
    ap.add_argument("--workdir", default=None, help="dir to clone repos into (default: temp)")
    ap.add_argument("--keep", action="store_true", help="keep cloned repos after run")
    args = ap.parse_args()

    if not SCANNER.exists():
        print(f"ERROR: scanner not found at {SCANNER}"); return 1
    manifest = json.loads(MANIFEST.read_text())

    workdir = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="mcp-authscan-gt-"))
    workdir.mkdir(parents=True, exist_ok=True)
    print(f"workdir: {workdir}\n")

    total_expected = total_found = 0
    failures = []

    for case in manifest["cases"]:
        name = case["name"]
        # Local fixture case: scan a path in the repo, no clone/network.
        if "path" in case:
            dest = (MANIFEST.parent.parent / case["path"]).resolve()
            print(f"[local]  {name}: {dest}")
            scan = run([sys.executable, str(SCANNER), str(dest)])
            out = scan.stdout
            for exp in case["must_detect"]:
                total_expected += 1
                lines = out.splitlines()
                rule_ok = False
                for i, line in enumerate(lines):
                    if f"] {exp['rule']} " in line and exp["match"] in "\n".join(lines[i:i+3]):
                        rule_ok = True; break
                if rule_ok:
                    total_found += 1
                    print(f"  PASS  {exp['rule']}  {exp['match']}")
                else:
                    failures.append((name, exp["rule"], exp["match"], "not detected"))
                    print(f"  FAIL  {exp['rule']}  {exp['match']}  <- NOT re-detected")
            for exp in case.get("must_not_detect", []):
                total_expected += 1
                fired = any(f"] {exp['rule']} " in line for line in out.splitlines())
                if not fired:
                    total_found += 1
                    print(f"  PASS  {exp['rule']}  (correctly absent)")
                else:
                    failures.append((name, exp["rule"], "(must be absent)", "false positive"))
                    print(f"  FAIL  {exp['rule']}  <- FIRED but must stay silent (FP regression)")
            continue
        repo = case["repo"]
        dest = workdir / name
        if not dest.exists():
            print(f"[clone] {repo}")
            r = run(["git", "clone", "--depth", "1", repo, str(dest)])
            if r.returncode != 0:
                print(f"  CLONE FAILED: {r.stderr.strip().splitlines()[-1] if r.stderr else '?'}")
                for exp in case["must_detect"]:
                    failures.append((name, exp["rule"], exp["match"], "clone failed"))
                    total_expected += 1
                continue
        # run the scanner once, reuse output for all cases in this repo
        scan = run([sys.executable, str(SCANNER), str(dest)])
        out = scan.stdout
        print(f"[scan]  {name}: {out.strip().splitlines()[-1] if out.strip() else 'no output'}")
        for exp in case["must_detect"]:
            total_expected += 1
            # a seed is re-detected if a line with its rule tag AND its file:line match appears
            hit = any(
                exp["match"] in line
                for line in out.splitlines()
            )
            # also confirm the matching finding carries the right rule id nearby
            rule_ok = False
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if f"] {exp['rule']} " in line:
                    # the file:line appears on the next 1-2 lines of that finding block
                    window = "\n".join(lines[i:i+3])
                    if exp["match"] in window:
                        rule_ok = True
                        break
            if rule_ok:
                total_found += 1
                print(f"  PASS  {exp['rule']}  {exp['match']}")
            else:
                failures.append((name, exp["rule"], exp["match"], exp.get("note", "")))
                print(f"  FAIL  {exp['rule']}  {exp['match']}  <- NOT re-detected")
        print()

    if not args.keep and not args.workdir:
        run(["rm", "-rf", str(workdir)])

    print("=" * 60)
    print(f"Ground truth: {total_found}/{total_expected} seed findings re-detected")
    if failures:
        print("\nREGRESSIONS:")
        for name, rule, match, note in failures:
            print(f"  {name}  {rule}  {match}  ({note})")
        print("\nRESULT: FAIL")
        return 1
    print("\nRESULT: PASS - all seed findings re-detected")
    return 0

if __name__ == "__main__":
    sys.exit(main())
