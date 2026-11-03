import ast, json, subprocess, sys
def main():
    p, name, log, prefix = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    out = subprocess.run([sys.executable, "mcp_authscan/conformance_token.py", log, prefix], capture_output=True, text=True)
    verdict = ast.literal_eval(out.stdout.strip())[0]
    rows = json.load(open(p))
    n = 0
    for r in rows:
        if r["client"] == name:
            r["token_response_iss"] = verdict
            n += 1
    json.dump(rows, open(p, "w"))
    print(name, "token_response_iss", verdict, n)
main()
