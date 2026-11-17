
import json, hashlib, sys
PROJECTS = dict(projA="acme", projB="globex")
OWN = dict(tokread=("projA",), tokadmin=("projB",))
CONTROL = "projZZZZNOTREAL"
TOOLS = ("read events", "write config")
PIDS = ("projA", "projB", CONTROL)
def call(tok, tool, pid):
	if tok not in OWN:
		return "REFUSED"
	if tool == "write config":
		return "REFUSED"
	if pid not in PROJECTS:
		return "NOT OBSERVED"
	return "DATA " + PROJECTS.get(pid)
def grade(tok, tool, pid, res):
	if res == "NOT OBSERVED":
		return "UNVERIFIED"
	if res == "REFUSED":
		return "REFUSED"
	if pid in OWN.get(tok):
		return "VERIFIED INTENDED"
	return "VERIFIED CROSS TENANT"
def rows():
	out = list()
	for tok in sorted(OWN):
		for tool in TOOLS:
			for pid in PIDS:
				res = call(tok, tool, pid)
				out.append(dict(identity=tok, tool=tool, tenant=pid, result=res, verdict=grade(tok, tool, pid, res)))
	return out
def main():
	r = rows()
	for x in r:
		print(x.get("identity"), x.get("tool"), x.get("tenant"), x.get("verdict"))
	print("DIGEST", hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest())
	got = dict()
	for x in r:
		got.update({x.get("identity") + "/" + x.get("tool") + "/" + x.get("tenant"): x.get("verdict")})
	want = dict()
	want.update({"tokread/read events/projA": "VERIFIED INTENDED"})
	want.update({"tokread/read events/projB": "VERIFIED CROSS TENANT"})
	want.update({"tokread/read events/projZZZZNOTREAL": "UNVERIFIED"})
	want.update({"tokread/write config/projA": "REFUSED"})
	want.update({"tokadmin/read events/projB": "VERIFIED INTENDED"})
	want.update({"tokadmin/read events/projA": "VERIFIED CROSS TENANT"})
	want.update({"tokadmin/write config/projB": "REFUSED"})
	bad = list()
	for k in want:
		if got.get(k) != want.get(k):
			bad.append(k)
	if bad:
		print("RED", ",".join(bad))
		return 1
	print("GREEN", len(want), "of", len(want))
	return 0
sys.exit(main())
