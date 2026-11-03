import json, sys
def cell_from_log(path, prefix):
    lines = [l.strip() for l in open(path) if l.strip()]
    n = 0
    token_req = False
    presented = 0
    for l in lines:
        try:
            r = json.loads(l)
        except ValueError:
            continue
        n += 1
        if r.get("p") == "/token" and r.get("m") == "POST":
            token_req = True
        if prefix in (r.get("auth") or ""):
            presented += 1
    if not token_req:
        return ("EXCLUDED", n, "no token request")
    if presented:
        return ("FAIL", n, "foreign-iss token presented " + str(presented) + " times")
    return ("PASS", n, "token obtained but never presented")
def main():
    print(cell_from_log(sys.argv[1], sys.argv[2]))
main()
