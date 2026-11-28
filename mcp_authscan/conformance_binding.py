import json, os, shutil, subprocess, sys, time
# Paths come from the environment, defaulting to the repo-local tree conformance/run_rows.sh builds.
CONF = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "conformance")
H = os.path.abspath(os.environ.get("HARNESS", os.path.join(CONF, ".work")))
L = os.path.join(H, "logs")
MATRIX = os.path.abspath(os.environ.get("MATRIX", "matrix.json"))
TS = os.environ.get("TS_DRIVER", os.path.join(H, "t3.mjs"))
PY = {
    "python-sdk 1.29.1": os.environ.get("PY_MCP_1_29_1", os.path.join(CONF, ".envs", "mcp-1.29.1", "bin", "python")),
    "python-sdk 1.30.0": os.environ.get("PY_MCP_1_30_0", os.path.join(CONF, ".envs", "mcp-1.30.0", "bin", "python")),
    "fastmcp 4.1.2": os.environ.get("PY_FASTMCP_4_1_2", os.path.join(CONF, ".envs", "fastmcp-4.1.2", "bin", "python")),
}
CLIENTS = ["python-sdk 1.29.1", "python-sdk 1.30.0", "fastmcp 4.1.2", "typescript-sdk 1.32.2"]
def need(path):
    if not os.path.exists(path):
        raise SystemExit("missing: " + path)
    return path
def lines(p):
    f = os.path.join(L, str(p) + ".jsonl")
    if not os.path.exists(f):
        return []
    return [x for x in open(f).read().splitlines() if x.strip()]
def start(mode, port):
    os.makedirs(L, exist_ok=True)
    f = open(os.path.join(H, "f" + str(port) + ".log"), "w")
    pr = subprocess.Popen([sys.executable, need(os.path.join(H, "fixture.py")), mode, str(port)], cwd=H, stdout=f, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    return pr
def clear_stores():
    for n in ["state.json", "s7.json", "store-run.json", "store-ts.json"]:
        p = os.path.join(H, n)
        if os.path.exists(p):
            os.remove(p)
    d = os.path.join(H, "fmstore")
    if os.path.isdir(d):
        shutil.rmtree(d)
def env_dir(name):
    """Per-version client tree for versions outside PY/TS (built by conformance/watch.py)."""
    return os.path.join(CONF, ".envs", name.replace(" ", "-"))
def drive(name, port):
    kind = name.split(" ")[0]
    if kind in ("python-sdk", "fastmcp"):
        py = PY.get(name) or os.path.join(env_dir(name), "bin", "python")
        script = "drive2.py" if kind == "python-sdk" else "drive3.py"
        cmd = [need(py), need(os.path.join(H, script)), str(port)]
    elif kind == "typescript-sdk":
        ts = TS if name == "typescript-sdk 1.32.2" else os.path.join(env_dir(name), "t3.mjs")
        cmd = ["node", need(ts), "http:" + "//127.0.0.1:" + str(port) + "/mcp", os.path.join(H, "store-ts.json")]
    else:
        raise SystemExit("unknown client kind: " + name)
    r = subprocess.run(cmd, cwd=H, capture_output=True, text=True, timeout=90)
    out = r.stdout + r.stderr
    if r.returncode != 0:
        raise RuntimeError("driver failed for " + name + " on " + str(port) + ": " + out[-400:])
    return out
def binding(name, p1, p2):
    clear_stores()
    for p in (p1, p2):
        f = os.path.join(L, str(p) + ".jsonl")
        if os.path.exists(f):
            os.remove(f)
    a = start("clean", p1)
    try:
        drive(name, p1)
        n1 = len(lines(p2))
        b = start("clean", p2)
        try:
            drive(name, p2)
        finally:
            b.terminate()
    finally:
        a.terminate()
    new = lines(p2)[n1:]
    leaked = [x for x in new if "at-clean-" + str(p1) in x]
    own = [x for x in new if "at-clean-" + str(p2) in x]
    if leaked:
        return "FAIL", len(leaked)
    if own:
        return "PASS", len(own)
    if not new:
        raise RuntimeError("fixture recorded nothing on " + str(p2) + ", harness did not run")
    return "NOT_OBSERVED", 0
def metadata(name, port):
    """metadata_issuer: the AS metadata names a foreign issuer (127.0.0.1:9999, a sink).
    PASS = read the metadata and stopped; FAIL = followed the foreign issuer or requested
    a token anyway; EXCLUDED = never reached the authorization step (graded by conformance_meta)."""
    from mcp_authscan.conformance_meta import cell_from_log
    clear_stores()
    f = os.path.join(L, str(port) + ".jsonl")
    if os.path.exists(f):
        os.remove(f)
    sink_log = os.path.join(H, "sink9999.log")
    if os.path.exists(sink_log):
        os.remove(sink_log)
    sk = subprocess.Popen([sys.executable, need(os.path.join(H, "sink.py"))], cwd=H,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        a = start("badmeta", port)
        try:
            drive(name, port)
        finally:
            a.terminate()
    finally:
        sk.terminate()
    if not lines(port):
        raise RuntimeError("fixture recorded nothing on " + str(port) + ", harness did not run")
    cell, n, _why = cell_from_log(f, sink_log)
    return cell, n
def recs(port):
    out = []
    for x in lines(port):
        try:
            out.append(json.loads(x))
        except ValueError:
            pass
    return out
def _follow(name, mode, port):
    """Run one follow-authorize flow against a fixture; return its parsed request log."""
    clear_stores()
    f = os.path.join(L, str(port) + ".jsonl")
    if os.path.exists(f):
        os.remove(f)
    a = start(mode, port)
    old = os.environ.get("FOLLOW_AUTHORIZE")
    os.environ["FOLLOW_AUTHORIZE"] = "1"
    try:
        out = drive(name, port)
    finally:
        a.terminate()
        if old is None:
            os.environ.pop("FOLLOW_AUTHORIZE", None)
        else:
            os.environ["FOLLOW_AUTHORIZE"] = old
    r = recs(port)
    if not [x for x in r if x.get("p") == "/authorize"]:
        raise RuntimeError("client never reached /authorize on " + str(port) + ": " + out[-300:])
    return r
def authiss(name, port):
    """authz_response_iss (RFC 9207; MCP draft "Authorization Response Validation", a client MUST):
    the authorization redirect carries iss naming a foreign issuer. FAIL = the code was sent to the
    token endpoint anyway; PASS = no token request, and only if the same flow with a correct
    redirect (control, port+1) does request a token; otherwise EXCLUDED."""
    tokens = lambda r: [x for x in r if x.get("p") == "/token" and x.get("m") == "POST"]
    bad = tokens(_follow(name, "badauthiss", port))
    if bad:
        return "FAIL", len(bad)
    control = tokens(_follow(name, "clean", port + 1))
    return ("PASS", len(control)) if control else ("EXCLUDED", 0)
CHECKS = {"credential_binding": lambda name: binding(name, 9271, 9272),
          "metadata_issuer": lambda name: metadata(name, 9281),
          "authz_response_iss": lambda name: authiss(name, 9291)}
def main():
    names = sys.argv[1:] if len(sys.argv) > 1 else CLIENTS
    rows = json.load(open(MATRIX))
    for name in names:
        for col, run in CHECKS.items():
            cell, n = run(name)
            for r in rows:
                if r["client"] == name:
                    r[col] = cell
            print(name, col, cell, n, flush=True)
            json.dump(rows, open(MATRIX, "w"), indent=4)
if __name__ == "__main__":
    main()
