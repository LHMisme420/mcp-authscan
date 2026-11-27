"""Run the labeled MCP AuthScan dataset against local fixtures and record every probe.

Usage, from the repo root:  python3 bench/dataset/run_dataset.py

Each case starts fixture_oauth.py on loopback with the case's environment, scans
it with --json, and writes one row per probe to rows.jsonl: the label (or null),
the observed status, severity and limitation, and the report_hash of the scan.
Only labeled probes are scored. Nothing leaves the machine.
"""
import datetime
import hashlib
import importlib.metadata
import json
import os
import platform
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SCAN = ["mcp-authscan", "--json", "--contact", "dataset@example.invalid",
        "--authorized-by", "dataset runner", "--auth-basis", "own fixture, local loopback",
        "--allow-private"]


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_listening(port, proc, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def run_case(case, default_fixture):
    port = free_port()
    base = "http://127.0.0.1:%d" % port
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    env.update(case.get("env", {}), PORT=str(port))
    fixture = os.path.join(ROOT, case.get("fixture", default_fixture))
    argv = [sys.executable, fixture] + ([str(port)] if case.get("port_arg") else [])
    fx = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        if not wait_listening(port, fx):
            raise RuntimeError("fixture did not start for " + case["id"])
        scan_env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
        scan_env.update({k: v.replace("{base}", base) for k, v in case.get("scan_env", {}).items()})
        r = subprocess.run(SCAN + [base + "/mcp"], capture_output=True,
                           text=True, env=scan_env, timeout=180)
    finally:
        fx.terminate()
        fx.wait()
    try:
        report = json.loads(r.stdout)
    except ValueError:
        report = None  # no JSON report (e.g. exit 4, not an MCP server)
    return r.returncode, report


def main():
    spec = json.load(open(os.path.join(HERE, "cases.json"), encoding="utf-8"))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = os.path.join(HERE, "results", "run-" + stamp)
    os.makedirs(out)
    rows, scored, hit = [], 0, 0
    for case in spec["cases"]:
        code, report = run_case(case, spec["fixture"])
        emitted = report is not None
        report = report or {}
        labels = dict(spec.get("default_labels", {}) if case.get("defaults", True) else {})
        labels.update(case.get("labels", {}))
        seen = {p["name"]: p for p in report.get("probes", [])}
        seen["_exit_code"] = {"status": code}
        seen["_findings_count"] = {"status": len(report.get("findings", []))}
        for name in sorted(set(seen) | set(labels)):
            p = seen.get(name, {})
            label = labels.get(name)
            observed = p.get("status")
            match = None if label is None else (observed == label)
            if match is not None:
                scored += 1
                hit += match
            rows.append({"case": case["id"], "env": case.get("env", {}), "probe": name, "label": label,
                         "observed": observed, "severity": p.get("severity"),
                         "limitation": p.get("limitation"), "match": match, "exit_code": code, "report_emitted": emitted,
                         "report_hash": report.get("report_hash")})
            if match is False:
                print("MISS %s %s label=%s observed=%s" % (case["id"], name, label, observed))
        print("case %-38s exit %d" % (case["id"], code))
    with open(os.path.join(out, "rows.jsonl"), "w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    git = lambda *a: subprocess.run(["git", "-C", ROOT, *a], capture_output=True, text=True).stdout.strip()
    summary = {"schema": "mcp-authscan-dataset-run-v1", "run": stamp,
               "scanner_version": importlib.metadata.version("mcp-authscan"),
               "repo_commit": git("rev-parse", "HEAD"), "repo_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
               "python": platform.python_version(), "cases": len(spec["cases"]), "rows": len(rows),
               "labeled_rows": scored, "labeled_hit": hit, "labeled_miss": scored - hit,
               "cases_sha256": hashlib.sha256(open(os.path.join(HERE, "cases.json"), "rb").read()).hexdigest()}
    with open(os.path.join(out, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    with open(os.path.join(out, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for name in ("rows.jsonl", "summary.json"):
            f.write("%s  %s\n" % (hashlib.sha256(open(os.path.join(out, name), "rb").read()).hexdigest(), name))
    print("\nDATASET %d cases, %d rows, labeled %d/%d hit -> %s" % (len(spec["cases"]), len(rows), hit, scored, out))
    return 0 if hit == scored else 1


if __name__ == "__main__":
    sys.exit(main())
