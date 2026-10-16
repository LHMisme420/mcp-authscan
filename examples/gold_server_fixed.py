#!/usr/bin/env python3
# Fixed twin of vulnerable_gold_server.py: E1/E2/E3 must stay silent here.
import json, sys, logging
logging.basicConfig(level=logging.INFO, format='%(message)s',
                   handlers=[logging.StreamHandler()])
logger = logging.getLogger()

data = {}

def handle(req):
    m = req.get("method")
    if "id" not in req:
        return None  # notification: no response
    if m == "initialize":
        return {"jsonrpc":"2.0","id":req["id"],"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"Gold","version":"1.0"}}}
    if m == "tools/list":
        return {"jsonrpc":"2.0","id":req["id"],"result":{"tools":[
            {"name":"store","description":"Store data","inputSchema":{"type":"object","properties":{"d":{"type":"string"}}}},
            {"name":"read","description":"Read your data","inputSchema":{"type":"object"}},
            {"name":"inject","description":"Injection test","inputSchema":{"type":"object"}}
        ]}}
    if m == "tools/call":
        params = req.get("params", {})
        tool = params.get("name")
        args = params.get("arguments", {})
        sid = params.get("_meta", {}).get("session_id")
        if not sid:
            return {"jsonrpc":"2.0","id":req["id"],"error":{"code":-32602,"message":"session_id required"}}

        if tool == "store":
            d = args.get("d", "")
            data[sid] = d
            logger.info("stored %d bytes for session %s", len(d), sid)
            return {"jsonrpc":"2.0","id":req["id"],"result":{"content":[{"type":"text","text":"Stored"}]}}

        if tool == "read":
            return {"jsonrpc":"2.0","id":req["id"],"result":{"content":[{"type":"text","text":data.get(sid, "")}]}}

        if tool == "inject":
            return {"jsonrpc":"2.0","id":req["id"],"result":{"content":[{"type":"text","text":"Injection test: no instructions returned."}]}}

    return {"jsonrpc":"2.0","id":req["id"],"error":{"code":-32601,"message":"Method not found"}}

for line in sys.stdin:
    try:
        resp = handle(json.loads(line))
        if resp is not None:
            print(json.dumps(resp), flush=True)
    except Exception as e:
        logger.error("bad request: %s", type(e).__name__)
