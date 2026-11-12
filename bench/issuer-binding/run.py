import glob, json, os, subprocess

HERE = "bench/issuer-binding"
SPEC = HERE + "/issuer-binding.expected.json"
spec = json.load(open(SPEC))
fixture = next(iter(glob.glob("run?issuer?binding.py")))

def interp(ver):
path = "/tmp/bench" + ver.replace(".", "")
if not os.path.exists(path + "/bin/python"):
subprocess.run("python3 -m venv " + path, shell=True, check=True)
subprocess.run(path + "/bin/pip -q install fastmcp==" + ver, shell=True, check=True)
return path

bad = 0
total = 0
for case in spec.get("cases"):
client = case.get("client")
mode = case.get("mode")
want = case.get("expected")
ver = client.split(" ").pop()
cmd = interp(ver) + "/bin/python " + fixture
if mode == "expect-issuer":
cmd = cmd + " --expect-issuer"
finished = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
got = "NO VERDICT"
for line in finished.stdout.splitlines():
if line.startswith("verdict:"):
got = line.split(":", 1).pop().strip()
total = total + 1
if got == want:
print("ok " + client + " " + mode + ": " + got)
else:
bad = bad + 1
print("DIVERGED " + client + " " + mode + ": expected " + str(want) + ", got " + got)

print("")
if bad == 0:
print("MATCH: all " + str(total) + " cases as expected")
else:
print("DIVERGED: " + str(bad) + " of " + str(total) + " cases")
raise SystemExit(1)
