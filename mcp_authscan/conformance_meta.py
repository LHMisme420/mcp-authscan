import json, os, sys
def cell_from_log(path, sink):
    lines = [l.strip() for l in open(path) if l.strip()]
    n = 0
    token_req = False
    as_meta = False
    for l in lines:
        try:
            r = json.loads(l)
        except ValueError:
            continue
        n += 1
        if r.get("p") == "/token" and r.get("m") == "POST":
            token_req = True
        if r.get("p") == "/.well-known/oauth-authorization-server" and r.get("m") == "GET":
            as_meta = True
    if sink and os.path.exists(sink) and os.path.getsize(sink) > 0:
        return ("FAIL", n, "followed the foreign issuer to 9999")
    if token_req:
        return ("FAIL", n, "token requested despite mismatched issuer")
    if as_meta:
        return ("PASS", n, "read authorization metadata, never requested a token")
    return ("EXCLUDED", n, "never reached the authorization step")
def main():
    sink = sys.argv[2] if len(sys.argv) > 2 else ""
    print(cell_from_log(sys.argv[1], sink))
main()
