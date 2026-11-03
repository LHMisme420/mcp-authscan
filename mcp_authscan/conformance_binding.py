import json, os, shutil, subprocess, sys, time
H = os.path.abspath(os.environ.get("HARNESS", os.path.expanduser("~/matrix/harness")))
L = os.path.join(H, "logs")
MATRIX = os.path.abspath(os.environ.get("MATRIX", "matrix.json"))
TS = os.environ.get("TS_DRIVER", os.path.expanduser("~/matrix/ts/t3.mjs"))
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
def drive(name, port):
    if name == "python-sdk 1.29.1":
        cmd = [os.path.expanduser("~/matrix/.venv-mcp1291/bin/python"), need(os.path.join(H, "drive2.py")), str(port)]
    elif name == "python-sdk 1.30.0":
        cmd = [sys.executable, need(os.path.join(H, "drive2.py")), str(port)]
    elif name == "fastmcp 4.1.2":
        cmd = [os.path.expanduser("~/matrix/.venv-fm/bin/python"), need(os.path.join(H, "drive3.py")), str(port)]
    else:
        cmd = ["node", need(TS), "http:" + "//127.0.0.1:" + str(port) + "/mcp", os.path.join(H, "store-ts.json")]
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
def main():
    names = sys.argv[1:] if len(sys.argv) > 1 else CLIENTS
    rows = json.load(open(MATRIX))
    for name in names:
        cell, n = binding(name, 9271, 9272)
        for r in rows:
            if r["client"] == name:
                r["credential_binding"] = cell
        print(name, "credential_binding", cell, n, flush=True)
        json.dump(rows, open(MATRIX, "w"), indent=4)
main()
