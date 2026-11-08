import io
import json
import sys

from mcp_authscan import client_check

SURFACE = "client"


def assess(client_python, expected_issuer=None, client_kind="python", client_node="node", node_cwd=".", client_name=None):
    buf = io.StringIO()
    real = sys.stdout
    sys.stdout = buf
    try:
        code = client_check.run(client_python, client_name, expected_issuer, client_kind=client_kind, client_node=client_node, node_cwd=node_cwd)
    finally:
        sys.stdout = real
    payload = json.loads(buf.getvalue() or "{}")
    rec = {"surface": SURFACE, "verdict": payload.get("verdict"), "kind": payload.get("kind", client_kind), "client": payload.get("client", client_name), "reason": payload.get("reason"), "touches": payload.get("touches") or [], "captured": payload.get("captured") or [], "code": code}
    if rec["verdict"] == "EXCLUDED":
        rec["prerequisite"] = rec["reason"]
    return rec
