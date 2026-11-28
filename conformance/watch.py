"""SDK release watch: re-run credential_binding against every new MCP client release.

For each tracked client, look up its latest published version. If it has not been
measured yet, build it from a clean environment, run the same credential_binding
check that produced matrix.json, save the exact dependency lock, and append a
dated record to conformance/watch/log.jsonl comparing it with the previous
measured version of that client. Nothing is graded that matrix.json does not grade.

Usage: python conformance/watch.py [--dry-run]
"""
import datetime, hashlib, json, os, shutil, subprocess, sys, urllib.request

CONF = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(CONF)
WATCH = os.path.join(CONF, "watch")
LOG = os.path.join(WATCH, "log.jsonl")
LOCKS = os.path.join(WATCH, "locks")
WORK = os.path.join(CONF, ".work")

COLUMNS = ("credential_binding", "metadata_issuer", "authz_response_iss")

# client kind -> (registry, package)
CLIENTS = {
    "python-sdk": ("pypi", "mcp"),
    "fastmcp": ("pypi", "fastmcp"),
    "typescript-sdk": ("npm", "@modelcontextprotocol/sdk"),
}


def latest(registry, package):
    url = ("https://pypi.org/pypi/%s/json" % package if registry == "pypi"
           else "https://registry.npmjs.org/%s/latest" % package)
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.load(r)
    return data["info"]["version"] if registry == "pypi" else data["version"]


def vkey(v):
    return tuple(int(p) if p.isdigit() else 0 for p in v.replace("-", ".").split("."))


def measured():
    """(kind, version) -> {column: verdict}, from matrix.json plus the watch log (later records win)."""
    seen = {}
    for row in json.load(open(os.path.join(ROOT, "matrix.json"))):
        kind, _, ver = row["client"].partition(" ")
        seen[(kind, ver)] = {c: row[c] for c in COLUMNS if c in row}
    if os.path.exists(LOG):
        for line in open(LOG):
            if line.strip():
                r = json.loads(line)
                seen.setdefault((r["client"], r["version"]), {}).update({c: r[c] for c in COLUMNS if c in r})
    return seen


def complete(seen, kind, version):
    return all(c in seen.get((kind, version), {}) for c in COLUMNS)


def previous(seen, kind, version, column="credential_binding"):
    older = sorted((v for (k, v) in seen if k == kind and vkey(v) < vkey(version) and column in seen[(k, v)]), key=vkey)
    return {"version": older[-1], column: seen[(kind, older[-1])][column]} if older else None


def build(kind, version):
    """Build the client from a clean environment; return (lock text, lock sha256)."""
    name = "%s %s" % (kind, version)
    d = os.path.join(CONF, ".envs", name.replace(" ", "-"))
    shutil.rmtree(d, ignore_errors=True)
    if kind == "typescript-sdk":
        os.makedirs(d)
        json.dump({"private": True, "type": "module",
                   "dependencies": {"@modelcontextprotocol/sdk": version}},
                  open(os.path.join(d, "package.json"), "w"), indent=2)
        subprocess.run(["npm", "install", "--silent", "--no-audit", "--no-fund"], cwd=d, check=True)
        shutil.copy(os.path.join(CONF, "fixtures", "t3.mjs"), d)
        lock = open(os.path.join(d, "package-lock.json")).read()
    else:
        subprocess.run([sys.executable, "-m", "venv", d], check=True)
        pkg = CLIENTS[kind][1]
        subprocess.run([os.path.join(d, "bin", "pip"), "install", "-q", "%s==%s" % (pkg, version)], check=True)
        lock = subprocess.run([os.path.join(d, "bin", "pip"), "freeze"], check=True,
                              capture_output=True, text=True).stdout
    return lock, hashlib.sha256(lock.encode()).hexdigest()


def summary_line(r):
    parts = []
    for c in COLUMNS:
        if c not in r:
            continue
        p = (r.get("previous") or {}).get(c)
        part = "%s %s" % (c, r[c])
        if p:
            part += " (previous %s: %s)" % (p["version"], p[c])
        if c in (r.get("changed") or []):
            part += " **CHANGED**"
        parts.append(part)
    return "- %s %s: %s" % (r["client"], r["version"], "; ".join(parts))


def prepare_harness():
    shutil.rmtree(WORK, ignore_errors=True)
    os.makedirs(WORK)
    for f in os.listdir(os.path.join(CONF, "fixtures")):
        if f.endswith((".py", ".mjs")):
            shutil.copy(os.path.join(CONF, "fixtures", f), WORK)


def git_head():
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                              text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    dry = "--dry-run" in argv
    seen = measured()
    todo = []
    for kind, (registry, package) in CLIENTS.items():
        v = latest(registry, package)
        status = "already measured" if complete(seen, kind, v) else "NEW"
        print("%-15s latest %-10s %s" % (kind, v, status), flush=True)
        if status == "NEW":
            todo.append((kind, v))
    if dry or not todo:
        return 0
    os.environ.setdefault("HARNESS", WORK)
    prepare_harness()
    sys.path.insert(0, ROOT)
    from mcp_authscan import conformance_binding as cb
    os.makedirs(LOCKS, exist_ok=True)
    summary = []
    for kind, version in todo:
        lock, lock_sha = build(kind, version)
        ext = "package-lock.json" if kind == "typescript-sdk" else "lock.txt"
        lock_path = os.path.join(LOCKS, "%s-%s.%s" % (kind, version, ext))
        open(lock_path, "w").write(lock)
        name = "%s %s" % (kind, version)
        results = {}
        for col, run in cb.CHECKS.items():
            results[col] = run(name)
        prev = {c: previous(seen, kind, version, c) for c in COLUMNS}
        rec = {
            "checked_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "client": kind,
            "version": version,
            **{c: results[c][0] for c in COLUMNS},
            "evidence_requests": {c: results[c][1] for c in COLUMNS},
            "previous": prev,
            "changed": [c for c in COLUMNS if prev[c] and prev[c][c] != results[c][0]],
            "lock": os.path.relpath(lock_path, ROOT),
            "lock_sha256": lock_sha,
            "harness_commit": git_head(),
        }
        with open(LOG, "a") as f:
            f.write(json.dumps(rec, sort_keys=True) + "\n")
        seen[(kind, version)] = {c: rec[c] for c in COLUMNS}
        summary.append(summary_line(rec))
        print(summary_line(rec)[2:], flush=True)
    open(os.path.join(WORK, "summary.md"), "w").write("\n".join(summary) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
