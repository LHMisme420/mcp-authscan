import json,os,subprocess
B=os.path.expanduser("~/mcp-authscan/bench")
CMDS=[l.strip() for l in open(B+"/scanners.txt") if l.strip()]
URLS=[l.strip() for l in open(B+"/targets.txt") if l.strip()]
out=open(B+"/runs.jsonl","w")
for u in URLS:
 for c in CMDS:
  r=subprocess.run(c.replace("TARGET",u),shell=True,capture_output=True,text=True)
  rec={"target":u,"cmd":c.split()[0],"rc":r.returncode,"stdout":r.stdout,"stderr":r.stderr}
  print(json.dumps(rec),file=out)
  print(u,c.split()[0],r.returncode,len(r.stdout))
out.close()
