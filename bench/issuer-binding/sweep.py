"""Version sweep: run the issuer-binding harnesses against real client releases.

Usage, from the repo root:
    python3 bench/issuer-binding/sweep.py VENV_DIR

For each fastmcp version, VENV_DIR/fm-<version> must hold fastmcp==<version> and
mcp==2.3.0. For each SDK version, VENV_DIR/sdk-<version> must hold mcp==<version>.
Create them with:  python3 -m venv D && D/bin/pip install fastmcp==V mcp==2.3.0
Every client runs only against the local decoy in run_issuer_binding.py.
Writes results/sweep-<stamp>/rows.jsonl, summary.json and SHA256SUMS.
"""
import datetime
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
FASTMCP = ["4.0.0", "4.0.11", "4.1.0", "4.1.1", "4.1.2", "4.1.8", "4.2.0", "4.2.6"]
SDK = ["1.29.1", "1.30.0", "2.0.0", "2.3.0"]


def run(python, script, *args):
    r = subprocess.run([python, script, *args], cwd=HERE, capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout


def version(python, pkg):
    return subprocess.run([python, "-c", "import importlib.metadata as m;print(m.version(%r))" % pkg],
                          capture_output=True, text=True).stdout.strip()


def main(venvs):
    rows = []
    for v in FASTMCP:
        py = os.path.join(venvs, "fm-" + v, "bin", "python")
        for mode, args in (("default", ()), ("expect-issuer", ("--expect-issuer",))):
            code, out = run(py, "run_issuer_binding.py", *args)
            fields = dict(l.split(": ", 1) for l in out.splitlines() if l.startswith(("verdict: ", "reason: ")))
            rows.append({"harness": "run_issuer_binding.py", "client": "fastmcp", "version": version(py, "fastmcp"),
                         "mcp": version(py, "mcp"), "mode": mode, "verdict": fields.get("verdict"),
                         "reason": fields.get("reason"), "exit": code})
    for v in SDK:
        py = os.path.join(venvs, "sdk-" + v, "bin", "python")
        code, out = run(py, "run_issuer_binding_sdk.py")
        for line in out.splitlines():
            if line.startswith("{"):
                row = json.loads(line)
                rows.append({"harness": "run_issuer_binding_sdk.py", "client": "mcp (python-sdk)",
                             "version": version(py, "mcp"), "mcp": version(py, "mcp"), "mode": row.get("mode"),
                             "verdict": row.get("verdict"), "reason": row.get("reason"), "exit": code})
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(HERE, "results", "sweep-" + stamp)
    os.makedirs(out)
    with open(os.path.join(out, "rows.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    summary = {"schema": "mcp-authscan-client-sweep-v1", "run": stamp, "rows": len(rows),
               "verdicts": {k: sum(r["verdict"] == k for r in rows) for k in sorted({str(r["verdict"]) for r in rows})}}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    with open(os.path.join(out, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for n in ("rows.jsonl", "summary.json"):
            f.write("%s  %s\n" % (hashlib.sha256(open(os.path.join(out, n), "rb").read()).hexdigest(), n))
    for r in rows:
        print("%-16s %-7s %-13s %-9s %s" % (r["client"], r["version"], r["mode"], r["verdict"], (r["reason"] or "")[:70]))
    print(out)


if __name__ == "__main__":
    main(sys.argv[1])
