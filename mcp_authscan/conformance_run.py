import json, os, subprocess, sys, time
HARNESS = os.path.abspath(os.environ.get("HARNESS", os.path.expanduser("~/matrix/harness")))
LOGS = os.path.join(HARNESS, "logs")
FIXTURE = os.path.join(HARNESS, "fixture.py")
PY = sys.executable
DRIVERS = {
    "typescript-sdk 1.32.2": lambda u, s: ["node", os.path.expanduser("~/matrix/ts/t3.mjs"), u, s],
}
def url(port):
    return "http:" + "//127.0.0.1:" + str(port) + "/mcp"
def start(mode, port):
    f = open(os.path.join(HARNESS, "f" + str(port) + ".log"), "w")
    p = subprocess.Popen([PY, FIXTURE, mode, str(port)], cwd=HARNESS, stdout=f, stderr=subprocess.STDOUT)
    time.sleep(1.5)
    return p
def lines(port):
    p = os.path.join(LOGS, str(port) + ".jsonl")
    if not os.path.exists(p):
        return []
    return [x for x in open(p).read().splitlines() if x.strip()]
def run(name, port, store):
    cmd = DRIVERS[name](url(port), store)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "timeout"
def binding(name, p1, p2):
    store = os.path.expanduser("~/matrix/store-run.json")
    if os.path.exists(store):
        os.remove(store)
    a = start("clean", p1)
    run(name, p1, store)
    n1 = len(lines(p2))
    b = start("clean", p2)
    run(name, p2, store)
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
    name = sys.argv[1] if len(sys.argv) > 1 else "typescript-sdk 1.32.2"
    cell, n = binding(name, 9241, 9242)
    p = os.path.expanduser("~/mcp-authscan/matrix.json")
    rows = json.load(open(p))
    for r in rows:
        if r["client"] == name:
            r["credential_binding"] = cell
    json.dump(rows, open(p, "w"))
    print(name, "credential_binding", cell, n)
main()
