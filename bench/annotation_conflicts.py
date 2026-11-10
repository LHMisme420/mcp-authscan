import json,re,sys
RULES="ann-rules-2"
V="delete remove create update modify write add insert patch put post send submit execute run invoke cancel close revoke rotate reset restart deploy publish transfer purge wipe clear archive disable enable uninstall install upload push commit merge rename move grant assign invite trigger".split()
M=("only call","do not call","call this","use this","used to","this tool","call when","call to")
N=("not ","n't","never","cannot","can not","no need","without")
S=re.compile(r"[^a-zA-Z0-9]+")
def vb(t):
    l=(t or "").lower()
    o=[]
    for v in V:
        if re.search(r"\b"+v+r"\b",l):
            o.append(v)
    return o

def verdict(t):
    a=t.get("annotations")
    if not isinstance(a,dict) or a.get("readOnlyHint") is not True:
        return None
    n=str(t.get("name") or "")
    d=str(t.get("description") or "")
    np=[x.lower() for x in S.split(n) if x]
    nh=[v for v in V if v in np]
    if len(d.strip())<15:
        return ("UNCLEAR",nh[0] if nh else "",d[:60],"short-desc")
    dh=vb(d)
    for sent in re.split(r"[.!?;\n]",d):
        low=sent.lower()
        h=vb(sent)
        if not h:
            continue
        if any(x in low for x in N):
            return ("UNCLEAR",h[0],sent.strip()[:90],"negation")
        if any(x in low for x in M):
            return ("CONFLICT",h[0],sent.strip()[:90],"clause")
    if nh:
        return ("UNCLEAR",nh[0],d.strip()[:90],"name")
    if dh:
        return ("UNCLEAR",dh[0],d.strip()[:90],"verb-no-clause")
    return ("NO_CONFLICT","",d.strip()[:60],"")

KEY={"n":"name","d":"description","a":"annotations"}

def norm(t):
    if not isinstance(t,dict):
        return {}
    out={}
    for k,v in t.items():
        out[KEY.get(k,k)]=v
    return out

def tools_of(d):
    if isinstance(d,list):
        return d
    for k in ("tools","items","surface"):
        v=d.get(k)
        if isinstance(v,list):
            return v
        if isinstance(v,dict) and isinstance(v.get("tools"),list):
            return v["tools"]
    return []

def main(p):
    tools=[norm(t) for t in tools_of(json.load(open(p)))]
    rows=[];c={"CONFLICT":0,"UNCLEAR":0,"NO_CONFLICT":0}
    for t in tools:
        v=verdict(t)
        if v is None:
            continue
        c[v[0]]+=1
        rows.append({"name":t.get("name"),"verdict":v[0],"verb":v[1],"clause":v[2],"basis":v[3]})
    a=sum(c.values())
    print("rules",RULES,"seen",len(tools),"annotated",a)
    print("CONFLICT",c["CONFLICT"],"UNCLEAR",c["UNCLEAR"],"NO_CONFLICT",c["NO_CONFLICT"])
    if a:
        print("rate %.2f%%"%(100.0*c["CONFLICT"]/a))
    for r in sorted(rows,key=lambda x:x["name"] or ""):
        if r["verdict"]=="CONFLICT":
            print("-",r["name"],"|",r["verb"],"|",r["basis"],"|",r["clause"])
    json.dump({"rules":RULES,"counts":c,"rows":rows},open(p.rsplit(".",1)[0]+"-annotations.json","w"),indent=2,sort_keys=True)

main(sys.argv[1])
