import json,os,subprocess,sys,tempfile,zipfile
target=sys.argv[1]
repo='/home/lhmisme/mcp-authscan'
sys.path.insert(0,repo)
from mcp_authscan.releases import MANIFEST_HASHES
want=MANIFEST_HASHES.get(target)
if not want:
    print('NO PIN for',target);sys.exit(2)
tmp=tempfile.mkdtemp()
wd=os.path.join(tmp,'w');os.makedirs(wd)
d=subprocess.run([sys.executable,'-m','pip','download','--no-deps','--no-cache-dir','-d',wd,'mcp-authscan=='+target],capture_output=True,text=True)
if d.returncode!=0:
    print('DOWNLOAD FAILED',d.stderr[-400:]);sys.exit(2)
whl=[f for f in os.listdir(wd) if f.endswith('.whl')]
if not whl:
    print('NO WHEEL in',wd);sys.exit(2)
ex=os.path.join(tmp,'x')
zipfile.ZipFile(os.path.join(wd,whl[0])).extractall(ex)
code='import json;from mcp_authscan.report_verify import build_provenance;print(json.dumps(build_provenance()))'
env=dict(os.environ);env['PYTHONPATH']=ex
r=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,cwd=tmp,env=env)
if r.returncode!=0:
    print('IMPORT FAILED',r.stderr[-500:]);sys.exit(2)
got=json.loads(r.stdout.strip().splitlines()[-1])['tool_manifest']
print('wheel',whl[0])
print('pinned',want)
print('wheel-manifest',got)
print('MATCH' if got==want else 'DIVERGENCE')
sys.exit(0 if got==want else 1)
