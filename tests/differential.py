#!/usr/bin/env python3
"""
Differential coverage: mcp-authscan vs established SAST tools on the pinned corpus.

For each benchmark positive, runs mcp-authscan and whichever of {bandit, gosec,
semgrep} is installed and applicable to the repo's language, then reports whether
each tool flagged the SAME vulnerable file mcp-authscan's detector fired on - plus
each tool's total finding count, so noise is visible. Substantiates (or refutes)
the thesis that general scanners miss the auth-LOGIC bugs mcp-authscan targets.

Honesty guards: gosec that loads 0 files is reported "could-not-analyze
(go mod download needed)", NOT "no findings"; same for semgrep registry failure.
"flagged" means a finding in the expected file, printed so you can judge whether it's
the same bug or an adjacent/generic pattern.

    python3 tests/differential.py            # run installed tools
    python3 tests/differential.py --keep
Requires: git, python3, and any of bandit/gosec/semgrep you want compared.
"""
import argparse, json, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCANNER = ROOT / "mcp_authscan.py"
MANIFEST = Path(__file__).resolve().parent / "benchmark_manifest.json"
DETECTORS = {"A1", "A2", "A3", "A6", "A7", "A10"}


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
            return False
    return run(["git", "checkout", "-q", "FETCH_HEAD"], cwd=dest).returncode == 0


def lang_of(d):
    if list(d.rglob("go.mod")):
        return "go"
    if list(d.rglob("*.py")):
        return "py"
    if list(d.rglob("*.ts")) or list(d.rglob("*.tsx")) or list(d.rglob("package.json")):
        return "ts"
    return "?"


def _is_test(path):
    p = path.lower()
    return ("/test" in p or "/tests/" in p or "/__tests__/" in p
            or p.split("/")[-1].startswith("test_")
            or p.endswith("_test.go") or ".test." in p or ".spec." in p)

def match_file(path, near):
    if not near or _is_test(path):
        return False
    base = path.split("/")[-1]
    return any(base == n or path.endswith("/" + n) for n in near.values())


def mcp_authscan(d, expect, near):
    r = run([sys.executable, str(SCANNER), str(d), "--json"])
    try:
        F = json.loads(r.stdout)["findings"]
    except Exception:
        return "error", []
    det = [f for f in F if f["rule"] in DETECTORS or f["rule"].startswith("B") or f["rule"].startswith("C")]
    want = [f for f in det if f["rule"] in expect and (not near or any(n in f["file"] for n in near.values()))]
    return ("CATCH" if want else "miss"), want


def bandit_run(d, near):
    if not shutil.which("bandit"):
        return "n/a", 0, []
    r = run(["bandit", "-q", "-r", str(d), "-f", "json"])
    try:
        res = json.loads(r.stdout)["results"]
    except Exception:
        return "error", 0, []
    infile = [f'{x["filename"].split("/")[-1]}:{x["line_number"]} {x["test_id"]}'
              for x in res if match_file(x["filename"], near)]
    return ("flagged-file" if infile else "miss"), len(res), infile[:4]


def gosec_run(d, near):
    exe = shutil.which("gosec") or (str(ROOT.parent / "gosec") if (ROOT.parent / "gosec").exists() else None)
    if not exe:
        return "n/a", 0, []
    if shutil.which("go"):
        run(["go", "mod", "download"], cwd=d)
    r = run([exe, "-quiet", "-fmt", "json", "./..."], cwd=d)
    try:
        j = json.loads(r.stdout)
    except Exception:
        return "could-not-analyze (run: go mod download)", 0, []
    if int(j.get("Stats", {}).get("files", 0)) == 0:
        return "could-not-analyze (run: go mod download)", 0, []
    iss = j.get("Issues", [])
    infile = [f'{x["file"].split("/")[-1]}:{x["line"]} {x["rule_id"]}'
              for x in iss if match_file(x["file"], near)]
    return ("flagged-file" if infile else "miss"), len(iss), infile[:4]


def semgrep_run(d, near):
    if not shutil.which("semgrep"):
        return "n/a", 0, []
    r = run(["semgrep", "--config", "auto", "--json", "--quiet", str(d)])
    try:
        j = json.loads(r.stdout)
    except Exception:
        return "could-not-analyze (registry unreachable?)", 0, []
    if j.get("errors") and not j.get("results"):
        return "could-not-analyze (see semgrep errors)", 0, []
    res = j.get("results", [])
    infile = [f'{x["path"].split("/")[-1]}:{x["start"]["line"]} {x["check_id"].split(".")[-1]}'
              for x in res if match_file(x["path"], near)]
    return ("flagged-file" if infile else "miss"), len(res), infile[:4]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--workdir", default=None)
    args = ap.parse_args()
    m = json.loads(MANIFEST.read_text())
    wd = Path(args.workdir) if args.workdir else Path(tempfile.mkdtemp(prefix="authscan-diff-"))
    wd.mkdir(parents=True, exist_ok=True)

    print(f"tools present: bandit={bool(shutil.which('bandit'))} "
          f"gosec={bool(shutil.which('gosec') or (ROOT.parent/'gosec').exists())} "
          f"semgrep={bool(shutil.which('semgrep'))}\n")
    rows = []
    for c in m["positives"]:
        dest = wd / c["name"]
        if not fetch_at(c["repo"], c["commit"], dest):
            print(f"[ERR] {c['name']}: fetch failed"); continue
        lang = lang_of(dest)
        near = c.get("expect_near", {})
        expect = set(c.get("expect_detect", []))
        av, _ = mcp_authscan(dest, expect, near)
        if lang == "py":
            tv, tn, td = bandit_run(dest, near); tool = "bandit"
        elif lang == "go":
            tv, tn, td = gosec_run(dest, near); tool = "gosec"
        elif lang == "ts":
            tv, tn, td = semgrep_run(dest, near); tool = "semgrep"
        else:
            tv, tn, td, tool = "n/a", 0, [], "?"
        rows.append((c["name"], lang, ",".join(sorted(expect)) or "-", av, tool, tv, tn, td))
        print(f"[{lang}] {c['name']:22} mcp-authscan={av} ({','.join(sorted(expect)) or '-'})  "
              f"{tool}={tv}  total={tn}")
        for d in td:
            print(f"        {tool}: {d}")

    if not args.keep and not args.workdir:
        run(["rm", "-rf", str(wd)])
    print("\n" + "=" * 70)
    mc = sum(1 for r in rows if r[3] == "CATCH")
    tc = sum(1 for r in rows if r[5] == "flagged-file")
    print(f"mcp-authscan caught the auth bug: {mc}/{len(rows)}")
    print(f"comparator flagged the same file: {tc}/{len(rows)} "
          f"(printed above - judge whether it's the same bug or a generic/adjacent pattern)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
