import json,os,subprocess,sys,tempfile
from mcp_authscan.report_verify import verify
def reproduce(target,expected,extra):
    fd,path=tempfile.mkstemp(suffix=".json")
    os.close(fd)
    cmd=[sys.executable,"-m","mcp_authscan.monolith","--json","--allow-private","-o",path,target]+extra
    r=subprocess.run(cmd,capture_output=True,text=True)
    if not os.path.exists(path) or os.path.getsize(path)==0:
        print("NO_REPORT")
        print((r.stderr or "")[-400:])
        return 4
    got=json.load(open(path)).get("report_hash")
    status,detail=verify(path)
    print("REPRODUCED" if got==expected else "DIVERGED")
    print("expected %s"%expected)
    print("fresh    %s"%got)
    print("self-check %s: %s"%(status,detail))
    return 0 if got==expected else 1
if len(sys.argv)>2:
    sys.exit(reproduce(sys.argv[1],sys.argv[2],sys.argv[3:]))
