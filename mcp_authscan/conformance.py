import json, sys, hashlib
PROFILE = "2026.11.03.1"
COLS = ["metadata_issuer", "credential_binding", "token_response_iss"]
def render(rows):
    w = max(len(r["client"]) for r in rows) + 2
    out = []
    out.append("mcp-authscan client conformance")
    out.append("profile " + PROFILE)
    out.append("captured 2026-11-03")
    out.append("every cell captured by run, not by hand")
    out.append("snapshot of the versions listed, not maintained")
    out.append("")
    out.append("client".ljust(w) + "  ".join(c.ljust(20) for c in COLS))
    for r in rows:
        out.append(r["client"].ljust(w) + "  ".join(r[c].ljust(20) for c in COLS))
    out.append("")
    for r in rows:
        for c in COLS:
            if r[c] == "NOT_OBSERVED":
                out.append(r["client"] + " " + c + ": " + r.get("reason_" + c, "no reason recorded"))
    body = "\n".join(out)
    out.append("")
    out.append("sha256 " + hashlib.sha256(body.encode()).hexdigest())
    return "\n".join(out)
def main():
    rows = json.load(open(sys.argv[1]))
    print(render(rows))
main()
