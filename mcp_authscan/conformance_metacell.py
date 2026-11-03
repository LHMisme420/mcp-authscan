import ast, json, subprocess, sys
def main():
    p, name, log, sink = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    out = subprocess.run([sys.executable, "mcp_authscan/conformance_meta.py", log, sink], capture_output=True, text=True)
    verdict = ast.literal_eval(out.stdout.strip())[0]
    rows = json.load(open(p))
    n = 0
    for r in rows:
        if r["client"] == name:
            r["metadata_issuer"] = verdict
            n += 1
    json.dump(rows, open(p, "w"))
    print(name, "metadata_issuer", verdict, n)
main()
