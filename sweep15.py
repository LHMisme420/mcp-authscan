import sys
import glob
import importlib
d = glob.glob("mcp?authscan")[0]
m = importlib.import_module(d + ".transportprobe")
S = chr(47)
tally = {}
for line in open(sys.argv[1]):
    u = line.strip()
    if not u:
        continue
    if not u.startswith("http"):
        u = "https:" + S + S + u.lstrip(S)
    try:
        r = m.altprobe(u)
        tally[r.status] = tally.get(r.status, 0) + 1
        print(r.status, u, r.limitation)
    except Exception as e:
        tally["ERROR"] = tally.get("ERROR", 0) + 1
        print("ERROR", u, e)
print("----")
print(tally)
