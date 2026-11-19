import json,sys
from mcp_authscan.report_verify import verify,authenticity

def out(obj):
    sys.stdout.write(json.dumps(obj,separators=(",",":"))+"\n");sys.stdout.flush()

TOOL={"name":"verify","description":"Recompute the hash of an mcp-authscan report and check its signature.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Path to the report JSON"},"keys":{"type":"string","description":"Optional path to keys.json"}},"required":["path"]},"annotations":{"title":"Verify report","readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False}}

for line in sys.stdin:
    line=line.strip()
    if not line: continue
    req=json.loads(line)
    mid=req.get("id")
    method=req.get("method")
    params=req.get("params") or {}
    if method=="initialize":
        out({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":params.get("protocolVersion") or "2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-authscan-verify","version":"1.0.0"}}})
    elif method=="tools/list":
        out({"jsonrpc":"2.0","id":mid,"result":{"tools":[TOOL]}})
    elif method=="tools/call":
        args=params.get("arguments") or {}
        path=args.get("path") or ""
        try:
            verdict,detail=verify(path)
            payload=json.load(open(path,encoding="utf-8"))
            keys=json.load(open(args["keys"],encoding="utf-8")) if args.get("keys") else None
            text="VERDICT "+verdict+"\nDETAIL "+str(detail)+"\nSIGNATURE "+authenticity(payload,keys)
        except Exception as error:
            text="ERROR "+str(error)
        out({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":text}]}})
    elif mid is not None:
        out({"jsonrpc":"2.0","id":mid,"error":{"code":-32601,"message":"unknown method "+str(method)}})
