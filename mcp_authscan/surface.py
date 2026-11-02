"""Deterministic surface digest for MCP servers."""
import hashlib
import json

from .defpin import canonical_tools

PROMPT_FIELDS = ("name", "description", "arguments")
RESOURCE_FIELDS = ("uri", "name", "description", "mimeType")

KINDS = (
    ("tool", "tools", "name", None),
    ("prompt", "prompts", "name", PROMPT_FIELDS),
    ("resource", "resources", "uri", RESOURCE_FIELDS),
)


def compact(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_items(items, fields, sort_key):
    rows = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        row = {}
        for field in fields:
            if field in item:
                row[field] = item[field]
        rows.append(row)
    rows.sort(key=lambda row: str(row.get(sort_key) or ""))
    return rows


def surface_rows(surface, kind, key, sort_key, fields):
    surface = surface or {}
    if fields is None:
        return json.loads(canonical_tools(surface.get(key) or []))
    return canonical_items(surface.get(key), fields, sort_key)


def canonical_surface(surface):
    surface = surface or {}
    payload = {"instructions": surface.get("instructions") or ""}
    for _kind, key, sort_key, fields in KINDS:
        payload[key] = surface_rows(surface, _kind, key, sort_key, fields)
    return compact(payload)


def surface_digest(surface):
    return hashlib.sha256(canonical_surface(surface).encode("utf-8")).hexdigest()


def item_index(surface):
    surface = surface or {}
    index = {}
    for kind, key, sort_key, fields in KINDS:
        for row in surface_rows(surface, kind, key, sort_key, fields):
            name = str(row.get(sort_key) or "")
            index[kind + ":" + name] = {"hash": hashlib.sha256(compact(row).encode("utf-8")).hexdigest(), "row": row}
    return index

def collapsed(value):
    return " ".join(str(value or "").split())


def field_diffs(old, new):
    fields = sorted(set(old) | set(new))
    return [field for field in fields if old.get(field) != new.get(field)]


def whitespace_only(old, new, fields):
    return all(collapsed(old.get(field)) == collapsed(new.get(field)) for field in fields)


def label_change(old, new, fields):
    return "whitespace" if whitespace_only(old, new, fields) else "changed"


def instructions_change(before, after):
    old = str((before or {}).get("instructions") or "")
    new = str((after or {}).get("instructions") or "")
    if old == new:
        return None
    return {"key": "instructions:", "change": label_change({"i": old}, {"i": new}, ["i"]), "fields": ["instructions"], "before": old, "after": new}


def diff_surfaces(before, after):
    old_index = item_index(before)
    new_index = item_index(after)
    changes = []
    head = instructions_change(before, after)
    if head:
        changes.append(head)
    for key in sorted(set(old_index) | set(new_index)):
        old = old_index.get(key)
        new = new_index.get(key)
        if old is None:
            changes.append({"key": key, "change": "added", "fields": [], "before": None, "after": new["row"]})
        elif new is None:
            changes.append({"key": key, "change": "removed", "fields": [], "before": old["row"], "after": None})
        elif old["hash"] != new["hash"]:
            fields = field_diffs(old["row"], new["row"])
            changes.append({"key": key, "change": label_change(old["row"], new["row"], fields), "fields": fields, "before": old["row"], "after": new["row"]})
    return changes

BASELINE_VERSION = "2026.11.02.1"


def build_baseline(endpoint, captured):
    from datetime import datetime, timezone
    return {
        "version": BASELINE_VERSION,
        "target": endpoint,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "digest": captured.get("digest"),
        "surface": captured.get("surface") or {},
    }


def load_baseline(path):
    from pathlib import Path
    file = Path(path)
    if not file.exists():
        return None, "baseline not found: %s" % path
    try:
        doc = json.loads(file.read_text(encoding="utf-8"))
    except ValueError as exc:
        return None, "baseline was not JSON: %s" % exc
    if not isinstance(doc, dict) or not isinstance(doc.get("surface"), dict):
        return None, "baseline had no surface"
    return doc, None


def save_baseline(path, doc):
    from pathlib import Path
    Path(path).write_text(json.dumps(doc, indent=1, sort_keys=True), encoding="utf-8")
    return path


def drift_report(endpoint, captured, baseline):
    if not isinstance(baseline, dict):
        return {"state": "not_compared", "reason": "no baseline supplied", "changes": []}
    if baseline.get("target") != endpoint:
        return {"state": "refused", "reason": "baseline target %s does not match %s" % (baseline.get("target"), endpoint), "changes": []}
    if not captured.get("digest"):
        return {"state": "not_compared", "reason": "current surface was not captured", "changes": []}
    changes = diff_surfaces(baseline.get("surface") or {}, captured.get("surface") or {})
    return {"state": "drift" if changes else "unchanged", "reason": None, "changes": changes}
