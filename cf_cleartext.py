import http.client as h, json
H="mcp.cloudflare.com"
R="http://127.0.0.1:8765/callback"
def call(tag,Conn,path,body,hdr):
    c=Conn(H,timeout=20)
    c.request("POST",path,body=body,headers=hdr)
    r=c.getresponse()
    t=r.read().decode("utf-8","replace")
    print(tag,path,r.status,t[:400])
    return r.status,t
j={"Content-Type":"application/json"}
reg=json.dumps({"client_name":"cf-probe","redirect_uris":[R],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"})
s,t=call("https",h.HTTPSConnection,"/register",reg,j)
cid=None
try: cid=json.loads(t).get("client_id")
except Exception: pass
print("cid",cid)
f={"Content-Type":"application/x-www-form-urlencoded"}
b="grant_type=authorization_code&code=probe&client_id="+str(cid)+"&redirect_uri="+R
call("https",h.HTTPSConnection,"/token",b,f)
call("http",h.HTTPConnection,"/token",b,f)
