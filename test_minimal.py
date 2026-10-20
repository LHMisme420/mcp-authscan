import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError

try:
    req = Request("https://app.twigl.it/mcp", method="POST")
    req.add_header("Content-Type", "application/json")
    req.data = json.dumps({}).encode()
    
    with urlopen(req, timeout=5) as resp:
        print(f"HTTP {resp.status}")
        print(dict(resp.headers))
except HTTPError as e:
    print(f"HTTP {e.code}")
    print(dict(e.headers))
    print(e.read().decode())

