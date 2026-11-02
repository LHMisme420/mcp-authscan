import hashlib
import json

FIELDS = ("name", "description", "inputSchema", "annotations")


def canonical_tools(tools):
    rows = []
    for tool in tools:
        row = {}
        for field in FIELDS:
            if field in tool:
                row[field] = tool[field]
        rows.append(row)
    rows.sort(key=lambda r: r.get("name") or "")
    return json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def tools_digest(tools):
    return hashlib.sha256(canonical_tools(tools).encode("utf-8")).hexdigest()
