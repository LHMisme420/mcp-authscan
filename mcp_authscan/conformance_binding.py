import json, os, shutil, subprocess, sys, time
H = os.path.abspath(os.environ.get("HARNESS", os.path.expanduser("~/matrix/harness")))
L = os.path.join(H, "logs")
def lines(p):
    f = os.path.join(L, str(p) + ".jsonl")
    if not os.path.exists(f):
        return []
    return [x for x in open(f).read().splitlines() if x.strip()]
def start(mode, port):
    f = open(os.path.join(H, "f" + str(port) + ".log"), "w")
    pr = subprocess.Popen([sys.executable, os.path.join(H, "fixture.py"), mode, str(port)], cwd=H, stdout=f, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    return pr
def clear_stores():
    for n in ["state.json", "s7.json", "store-run.json"]:
        p = os.path.join(H, n)
        if os.path.exists(p):
            os.remove(p)
    d = os.path.join(H, "fmstore")
    if os.path.isdir(d):
        shutil.rmtree(d)
def drive(name, port):
    if name == "python-sdk 1.29.1":
        cmd = [os.path.expanduser("~/matrix/.venv-mcp1291/bin/python"), os.path.join(H, "drive2.py"), str(port)]
    elif name == "python-sdk 1.30.0":
        cmd = [sys.executable, os.path.join(H, "drive2.py"), str(port)]
    else:
        cmd = [os.path.expanduser("~/matrix/.venv-fm/bin/python"), os.path.join(H, "drive3.py"), str(port)]
    try:
        r = subprocess.run(cmd, cwd=H, capture_output=True, text=True, timeout=90)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "timeout"
def binding(name, p1, p2):
    clear_stores()
    for p in (p1, p2):
        f = os.path.join(L, str(p) + ".jsonl")
        if os.path.exists(f):
            os.remove(f)
    a = start("clean", p1)
    drive(name, p1)
    n1 = len(lines(p2))
    b = start("clean", p2)
    drive(name, p2)
    new = lines(p2)[n1:]
    leaked = [x for x in new if "at-clean-" + str(p1) in x]
    own = [x for x in new if "at-clean-" + str(p2) in x]
    a.terminate()
    b.terminate()
    if leaked:
        return "FAIL", len(leaked)
    if own:
        return "PASS", len(own)
    return "NOT_OBSERVED", 0
def main():
    name = sys.argv[1]
    cell, n = binding(name, 9271, 9272)
    p = os.path.expanduser("~/mcp-authscan/matrix.json")
    rows = json.load(open(p))
    for r in rows:
        if r["client"] == name:
            r["credential_binding"] = cell
    json.dump(rows, open(p, "w"))
    print(name, cell, n)
main()
