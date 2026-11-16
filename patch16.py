
import glob
d = glob.glob("mcp?authscan")[0]
P = d + "/target_probes.py"
M = d + "/monolith.py"
src = open(P).read()
if "originprobe" in src:
    print("already wired")
    raise SystemExit(0)
old1 = "t_rec = altprobe(target_url, allowed=allowed_hosts)"
print("anchor1:", src.count(old1))
if src.count(old1) != 1:
    raise SystemExit("anchor1 not exactly one")
src = src.replace(old1, old1 + chr(10) + "    o_rec = originprobe(target_url, allowed=allowed_hosts)")
old2 = "records = [rec, rate_rec, t_rec]"
print("anchor2:", src.count(old2))
src = src.replace(old2, "records = [rec, rate_rec, t_rec, o_rec]")
old3 = "t_findings(target_url, t_rec)"
print("anchor3:", src.count(old3))
src = src.replace(old3, old3 + " + o_findings(target_url, o_rec)")
imp = "from mcp_authscan.originprobe import originprobe, o_findings"
if imp not in src:
    src = src + chr(10) + imp + chr(10)
open(P, "w").write(src)
ms = open(M).read().replace("2026.11.16.1", "2026.11.16.2")
open(M, "w").write(ms)
print("wired, stamp 2026.11.16.2")
