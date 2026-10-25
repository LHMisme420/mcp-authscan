from urllib.request import Request, urlopen
from urllib.error import HTTPError
import json

payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "mcp-authscan", "version": "1.0.0"}
    }
}

req = Request("https://api.meant.run/mcp", method="POST")
req.add_header("User-Agent", "mcp-authscan/1.0.0")
req.add_header("Content-Type", "application/json")
req.add_header("Accept", "application/json, text/event-stream")
req.data = json.dumps(payload).encode()

try:
    with urlopen(req, timeout=5) as resp:
        pass
except HTTPError as e:
    print(f"HTTP {e.code}")
    www_auth = e.headers.get("WWW-Authenticate", "")
    print(f"WWW-Authenticate: {www_auth}")
    if e.fp:
        body = e.fp.read(200).decode(errors='ignore')
        print(f"Body: {body}")
