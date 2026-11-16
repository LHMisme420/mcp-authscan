import sys,os,threading,subprocess
D='/home/lhmisme/mcp-authscan/bench/adversarial'
sys.path.insert(0,D)
import adv as A
def run(extra):
    s=A.T(('127.0.0.1',0),A.H)
    threading.Thread(target=s.serve_forever,daemon=True).start()
    h='127.0.0.1:%d'%s.server_address[1]
    c=[sys.executable,'-m','mcp_authscan.monolith','http://'+h+'/mcp','--contact','b@example.invalid','--authorized-by','bench','--auth-basis','x','--allow-private','--allow-host',h]+extra
    p=subprocess.run(c,cwd='/home/lhmisme/mcp-authscan',capture_output=True,text=True,timeout=120)
    s.shutdown()
    return p.returncode,(p.stdout+p.stderr).upper()
a,t=run([])
print('default exit',a,'want 0','MATCH' if a==0 else 'DIVERGENCE')
print('zero-auth','MATCH' if 'ZERO-AUTH' in t else 'DIVERGENCE')
b,u=run(['--fail-on','medium'])
print('medium exit',b,'want 1','MATCH' if b==1 else 'DIVERGENCE')
