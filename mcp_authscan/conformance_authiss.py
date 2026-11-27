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
def drive(name, port):
    if name == "python-sdk 1.29.1":
        cmd = [need(PY[name]), need(os.path.join(H, "drive2.py")), str(port)]
    elif name == "python-sdk 1.30.0":
        cmd = [need(PY[name]), need(os.path.join(H, "drive2.py")), str(port)]
    elif name == "fastmcp 4.1.2":
        cmd = [need(PY[name]), need(os.path.join(H, "drive3.py")), str(port)]
    else:
        cmd = ["node", need(TS), "http:" + "//127.0.0.1:" + str(port) + "/mcp", os.path.join(H, "store-ts.json")]
    r = subprocess.run(cmd, cwd=H, capture_output=True, text=True, timeout=90)
    return r.returncode, (r.stdout + r.stderr)[-300:]
def recs(port):
    f = os.path.join(L, str(port) + ".jsonl")
    if not os.path.exists(f):
        raise RuntimeError("no fixture log for " + str(port))
    out = []
    for line in open(f).read().splitlines():
        if line.strip():
            out.append(json.loads(line))
    return out
def authiss(name, port):
    clear_stores()
    f = os.path.join(L, str(port) + ".jsonl")
    if os.path.exists(f):
        os.remove(f)
    a = start("badauthiss", port)
    try:
        code, out = drive(name, port)
    finally:
        a.terminate()
    r = recs(port)
    auth = [x for x in r if x.get("p") == "/authorize"]
    tok = [x for x in r if x.get("p") == "/token" and x.get("m") == "POST"]
    if not auth:
        raise RuntimeError("client never reached authorize on " + str(port) + ": " + out)
    if tok:
        return "FAIL", len(tok), code
    return "PASS", 0, code
def main():
    names = sys.argv[1:] if len(sys.argv) > 1 else CLIENTS
    rows = json.load(open(MATRIX))
    for name in names:
        cell, n, code = authiss(name, 9281)
        for r in rows:
            if r["client"] == name:
                r["authz_response_iss"] = cell
        print(name, "authz_response_iss", cell, n, "driver", code, flush=True)
        json.dump(rows, open(MATRIX, "w"), indent=4)
main()
