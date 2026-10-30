"""Deterministic fingerprint of the OAuth probe set, read from source by AST (nothing is imported
or run). tests/test_probe_set_stamp.py compares it with tests/probe_set_fingerprints.json so the
probe set cannot change while PROBE_SET_VERSION stays the same.

Covered (see CHANGELOG.md "Probe set stamps"):
  probe_order      the probe functions run_oauth_assessment calls, in order
  probe_records    every record(...) call reachable from each probe: probe_id, name,
                   prerequisites, severity, probe_class (literal or normalized expression)
  vocabulary       VALID_STATUSES and SEVERITY_ORDER (mcp_authscan/_common.py)
  code             normalized AST of every package-internal definition reachable from
                   run_oauth_assessment and count_probes (oauth_probes_v2, _common, counts,
                   errors, http_headers and the monolith helpers they import), docstrings removed
Not covered: monolith.main (CLI flags, exit codes, report rendering, findings built from FAIL
records, and the report accounting: its counts and coverage assignments), counts.coverage(),
render_probe, and resource_probes.py (not run by the scanner). Report accounting is how a report
adds up the records, not which probes run or what they decide, so it never needs a new stamp.

Normalization: comments and whitespace are not in the AST; docstrings, line/column positions,
expression contexts, Constant.kind and type comments are dropped, and fields that are None or
empty are skipped, so the dump is the same on every supported Python version.

Run `python3 -m tests.probe_set_fingerprint` to print the current fingerprint and components.
"""
import ast
import hashlib
import json
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "mcp_authscan"
ROOTS = ("run_oauth_assessment", "count_probes")
_SKIP_FIELDS = {"ctx", "kind", "type_comment", "lineno", "col_offset", "end_lineno", "end_col_offset"}


def _canon(node):
    """A version-independent, position-free serialization of an AST node."""
    if type(node).__name__ == "Index":       # Python 3.8 wraps a subscript in Index
        return _canon(node.value)
    if isinstance(node, ast.AST):
        fields = []
        for name in node._fields:
            if name in _SKIP_FIELDS:
                continue
            value = getattr(node, name, None)
            if value is None or value == []:
                continue
            if name == "body" and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                                                    ast.Module)):
                value = _strip_docstring(value)
            fields.append("%s=%s" % (name, _canon(value)))
        return "%s(%s)" % (type(node).__name__, ",".join(fields))
    if isinstance(node, list):
        return "[%s]" % ",".join(_canon(v) for v in node)
    return repr(node)


def _strip_docstring(body):
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        return body[1:]
    return body


class _Module:
    def __init__(self, name):
        self.name = name
        self.tree = ast.parse((PACKAGE / ("%s.py" % name)).read_text(encoding="utf-8"))
        self.defs = {}      # top-level name -> node
        self.imports = {}   # local name -> (module, name) for package-internal imports
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.defs[node.name] = node
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        self.defs[t.id] = node
            elif isinstance(node, ast.ImportFrom):
                self._add_import(node)

    def _add_import(self, node):
        mod = _internal(node)
        if mod:
            for alias in node.names:
                self.imports[alias.asname or alias.name] = (mod, alias.name)


def _internal(node):
    """Package-internal module name of a `from ... import`, or None."""
    if node.level == 1 and node.module:
        name = node.module
    elif node.level == 0 and node.module and node.module.startswith("mcp_authscan."):
        name = node.module.split(".", 1)[1]
    else:
        return None
    return name if (PACKAGE / ("%s.py" % name)).exists() else None


def _closure():
    """{"module.name": node} for every definition reachable from ROOTS."""
    modules, seen, todo = {}, {}, [("oauth_probes_v2", r) for r in ROOTS]
    while todo:
        mod_name, name = todo.pop()
        if mod_name not in modules:
            modules[mod_name] = _Module(mod_name)
        mod = modules[mod_name]
        key = "%s.%s" % (mod_name, name)
        if key in seen:
            continue
        if name in mod.imports:
            todo.append(mod.imports[name])
            continue
        node = mod.defs.get(name)
        if node is None:
            continue
        seen[key] = node
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name):
                todo.append((mod_name, sub.id))
            elif isinstance(sub, ast.ImportFrom):
                target = _internal(sub)
                if target:
                    todo.extend((target, a.name) for a in sub.names)
    return seen


def _probe_order(oauth):
    """Names of the probe_* functions run_oauth_assessment calls, in source order."""
    run = oauth.defs["run_oauth_assessment"]
    order = [(c.lineno, c.col_offset, c.func.id) for c in ast.walk(run)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id.startswith("probe_")]
    return [name for _, _, name in sorted(order)]


def _value(node):
    if type(node).__name__ == "Index":
        node = node.value
    try:
        return ast.literal_eval(node)
    except ValueError:
        return "<expr %s>" % _canon(node)


def _probe_records(closure):
    out = set()
    for key, node in closure.items():
        for call in ast.walk(node):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) \
                    and call.func.id in ("record", "_verdict_record"):
                fields = {}
                for kw in call.keywords:
                    if kw.arg in ("probe_id", "name", "prerequisites", "severity", "probe_class"):
                        fields[kw.arg] = _value(kw.value)
                if call.func.id == "_verdict_record" and len(call.args) >= 2:
                    fields.setdefault("probe_id", _value(call.args[0]))
                    fields.setdefault("name", _value(call.args[1]))
                out.add(json.dumps(fields, sort_keys=True, default=str))
    return sorted(out)


def _vocabulary():
    common = _Module("_common")
    return {n: sorted(_value(common.defs[n].value)) if n == "VALID_STATUSES" else list(_value(common.defs[n].value))
            for n in ("VALID_STATUSES", "SEVERITY_ORDER")}


def components():
    closure = _closure()
    oauth = _Module("oauth_probes_v2")
    parts = {
        "probe_order": _probe_order(oauth),
        "probe_records": _probe_records(closure),
        "vocabulary": _vocabulary(),
        "code": {k: _canon(closure[k]) for k in sorted(closure)},
    }
    return {k: hashlib.sha256(json.dumps(v, sort_keys=True).encode("utf-8")).hexdigest()
            for k, v in parts.items()}, parts


def fingerprint():
    hashes, _ = components()
    return hashlib.sha256(json.dumps(hashes, sort_keys=True).encode("utf-8")).hexdigest(), hashes


if __name__ == "__main__":
    fp, hashes = fingerprint()
    _, parts = components()
    print(json.dumps({"fingerprint": fp, "components": hashes, "probe_order": parts["probe_order"],
                      "code_definitions": sorted(parts["code"])}, indent=1))
