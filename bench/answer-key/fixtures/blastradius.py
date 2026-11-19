import sys, hashlib, json

def grade(listed, observed, intended, declared):
    rows = list()
    for t in sorted(listed):
        if t in observed:
            v = "VERIFIED INTENDED" if t in intended else "VERIFIED EXCESS"
        elif declared.get(t) is None:
            v = "UNKNOWN"
        else:
            v = "POTENTIAL DECLARED"
        rows.append(dict(tool=t, verdict=v, observed=t in observed))
    return rows

def digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest()

def selftest():
    listed = ("read docs", "write file", "delete account", "list users")
    observed = ("read docs",)
    intended = ("read docs",)
    declared = dict((("read docs", "read"), ("write file", "write"), ("list users", "read")))
    rows = grade(listed, observed, intended, declared)
    by = dict()
    for r in rows:
        by[r.get("tool")] = r.get("verdict")
    fails = list()
    if by.get("read docs") != "VERIFIED INTENDED":
        fails.append("intended")
    if by.get("write file") != "POTENTIAL DECLARED":
        fails.append("declared")
    if by.get("delete account") != "UNKNOWN":
        fails.append("undeclared")
    if by.get("list users") != "POTENTIAL DECLARED":
        fails.append("listed")
    for r in rows:
        print(r.get("tool"), "->", r.get("verdict"))
    print("DIGEST", digest(rows))
    if fails:
        print("RED", ",".join(fails))
        return 1
    print("GREEN 4 of 4")
    return 0

sys.exit(selftest())
