import json,os,subprocess,sys,time
B='bench/answer-key'
K=json.load(open(os.path.join(B,'key.json')))
hit=0
miss=0
for e in K:
    port=e['port']
    p=subprocess.Popen([sys.executable,os.path.join(B,'fixtures',e['fixture']+'.py'),str(port)])
    time.sleep(1.2)
    c=['mcp-authscan','--brief','--contact','lhmisme2011@gmail.com','--authorized-by','Leroy H. Mason','--auth-basis','Own fixture, local loopback','--allow-private','http://127.0.0.1:%d/mcp'%port]
    r=subprocess.run(c,capture_output=True,text=True)
    p.terminate()
    p.wait()
    L=[x for x in r.stdout.splitlines() if x.startswith('VERDICT')]
    v=None
    f=None
    if L:
        q=[x.strip() for x in L[0].split('|')]
        v=q[0].split()[1]
        f=int(q[2].split()[0])
    else:
        print("MISS "+e["fixture"]+" missing VERDICT evidence")
        miss += 1
        continue
    good=(v==e.get('expect_verdict') and f==e.get('expect_findings') and r.returncode==e['expect_exit'])
    if good:
        hit+=1
    else:
        miss+=1
    print(('HIT  ' if good else 'MISS ')+e['fixture']+' expect '+str(e['expect_verdict'])+' '+str(e['expect_findings'])+'f exit'+str(e['expect_exit'])+' got '+str(v)+' '+str(f)+'f exit'+str(r.returncode))
print('')
print('ANSWER KEY '+str(hit)+' hit '+str(miss)+' miss')
