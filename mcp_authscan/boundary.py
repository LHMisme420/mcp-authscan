import hashlib, json, sys

D = chr(95) * 2
GUARD = D + "name" + D
RUNAS = D + "main" + D

MATCH = "MATCH"
MISMATCH = "MISMATCH"
UNVERIFIED = "UNVERIFIED"
OVER = "overpermit"
UNDER = "underpermit"

def evaluate(declared, observed):
    d = (declared or "").strip().upper()
    o = (observed or "").strip().upper()
    if d not in ("ALLOW", "DENY") or o not in ("ALLOW", "DENY"):
        return UNVERIFIED, None
    if d == "DENY" and o == "ALLOW":
        return MISMATCH, OVER
    if d == "ALLOW" and o == "DENY":
        return MISMATCH, UNDER
    return MATCH, None

def row(cid, subject, declared, observed, basis):
    outcome, direction = evaluate(declared, observed)
    return {"id": cid, "subject": subject,
            "declared": (declared or "").strip().upper() or "UNKNOWN",
            "observed": (observed or "").strip().upper() or "UNKNOWN",
            "outcome": outcome, "direction": direction, "basis": basis}

def digest(rows):
    kept = []
    for r in sorted(rows, key=lambda x: x["id"]):
        kept.append({k: r[k] for k in ("id", "declared", "observed", "outcome", "direction")})
    blob = json.dumps(kept, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]

def report(rows):
    for r in rows:
        print("CONSISTENCY %s %s | declared %s | observed %s | %s | declaration check, not an authorization audit" % (r["id"], r["outcome"], r["declared"], r["observed"], r["subject"]))
    mis = [r for r in rows if r["outcome"] == MISMATCH]
    unv = [r for r in rows if r["outcome"] == UNVERIFIED]
    print("CONSISTENCY PROOF | %d mismatches | %d unverified | %d tested | digest %s" % (len(mis), len(unv), len(rows), digest(rows)))
    return 1 if mis else 0

def selftest():
    rows = [
        row("B1", "engineering reads engineering", "ALLOW", "ALLOW", "authorized policy"),
        row("B2", "engineering reads finance", "DENY", "ALLOW", "authorized policy"),
        row("B3", "unauthenticated call to restricted tool", "DENY", "DENY", "authorized policy"),
        row("B4", "delete tool declares readOnlyHint true", "DENY", "ALLOW", "tool annotation"),
        row("B5", "issuer published, no credential", "DENY", None, "no observation"),
    ]
    expect = {"B1": MATCH, "B2": MISMATCH, "B3": MATCH, "B4": MISMATCH, "B5": UNVERIFIED}
    for r in rows:
        assert r["outcome"] == expect[r["id"]], (r["id"], r["outcome"])
    code = report(rows)
    assert code == 1, code
    assert digest(rows) == digest([dict(r) for r in rows])
    print("SELFTEST OK")
    return 0

def run(path):
    data = json.load(open(path))
    rows = [row(x["id"], x.get("subject", ""), x.get("declared"), x.get("observed"), x.get("basis", "")) for x in data]
    return report(rows)

if globals().get(GUARD) == RUNAS:
    sys.exit(selftest() if len(sys.argv) < 2 else run(sys.argv[1]))
