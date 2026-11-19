import os
import json,sys
from mcp_authscan.report_verify import verify,authenticity

TOOL={"name":"verify","description":"Recompute the hash of an mcp-authscan report and check its signature.","inputSchema":{"type":"object","properties":{"path":{"type":"string","description":"Path to the report JSON"},"keys":{"type":"string","description":"Optional path to keys.json"}},"required":["path"]},"annotations":{"title":"Verify report","readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":False}}

def out(obj):
    sys.stdout.write(json.dumps(obj,separators=(",",":"))+"\n")
    sys.stdout.flush()

def serve():
    for line in sys.stdin:
        line=line.strip()
        if not line: continue
        req=json.loads(line)
        mid=req.get("id")
        method=req.get("method")
        params=req.get("params") or {}
        if method=="initialize":
            out({"jsonrpc":"2.0","id":mid,"result":{"protocolVersion":params.get("protocolVersion") or "2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"mcp-authscan-verify","version":"0.1.3"}}})
        elif method=="tools/list":
            out({"jsonrpc":"2.0","id":mid,"result":{"tools":[TOOL]}})
        elif method=="tools/call":
            args=params.get("arguments") or {}
            if params.get("name")!="verify": out({"jsonrpc":"2.0","id":mid,"error":{"code":-32602,"message":"unknown tool"}}); continue
            path=args.get("path") or "";base=os.path.realpath(os.path.expanduser(os.environ.get("MCP_AUTHSCAN_EVIDENCE") or "~/mcp-authscan-evidence"));real=os.path.realpath(os.path.expanduser(path)) if path else "";path=real
            keysp=os.path.realpath(os.path.expanduser(args["keys"])) if args.get("keys") else ""
            if keysp and not keysp.startswith(base+os.sep): out({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"ERROR keys must be inside the evidence directory"}]}}); continue
            if not real or not real.startswith(base+os.sep) or not os.path.isfile(real) or os.path.getsize(real)>5242880: out({"jsonrpc":"2.0","id":mid,"result":{"content":[{"type":"text","text":"ERROR report must be a file inside the evidence directory"}]}}); continue
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

if __name__=="__main__":
    serve()
