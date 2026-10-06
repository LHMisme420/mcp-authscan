#!/usr/bin/env python3
# A6-ast v0 (structural): method-equality authz gate whose sink is reachable when
# the gated method condition is false. Validated against anchored seed
# Ttokkime/mcp-gateway @ e2fa419 internal/proxy/proxy.go:144 (tools/list RBAC bypass).
#
# SCOPE NOTE: gates keyed on HTTP transport verbs (GET/POST/OPTIONS/...) are treated
# as routing/CORS, NOT MCP RBAC, and are deliberately ignored. This rule detects
# authorization scoped to MCP *protocol* methods only. A gateway that keys real authz
# off HTTP verbs is a documented blind spot, not a covered case.
import sys
import tree_sitter_go as tsgo
from tree_sitter import Language, Parser

GO = Language(tsgo.language())
try:
    _P = Parser(GO)
except TypeError:
    _P = Parser(); _P.set_language(GO)

AUTHZ = ("ToolAllowed", "Authorized", "Authorize", "Permitted", "Permit",
         "HasScope", "CanAccess", "HasPermission", "CheckAccess", "RBAC")
AUTHZ_SKIP = ("limiter", "breaker", "RateLimit", "ratelimit", "Cors", "CORS",
              "Preflight", "AllowedOrigin", "AllowedHeader", "AllowedMethod")
SINK = ("proxy", "Proxy", "forward", "Forward", "upstream", "Upstream",
        "ServeHTTP", "ReverseProxy", "io.Copy", "Catalog", "ListTools")

# HTTP transport verbs — a gate on these is routing/CORS, not MCP RBAC.
HTTP_VERBS = ("MethodGet", "MethodPost", "MethodPut", "MethodDelete",
              "MethodOptions", "MethodHead", "MethodPatch", "MethodConnect",
              "MethodTrace", '"GET"', '"POST"', '"PUT"', '"DELETE"',
              '"OPTIONS"', '"HEAD"', '"PATCH"')

def _txt(src, n): return src[n.start_byte:n.end_byte].decode("utf8", "replace")

def _walk(n):
    yield n
    for c in n.children:
        yield from _walk(c)

def _calls(src, node):
    for d in _walk(node):
        if d.type == "call_expression":
            fn = _txt(src, d.child_by_field_name("function") or d)
            yield d, fn

def _has_authz(src, node):
    for _, fn in _calls(src, node):
        if any(a in fn for a in AUTHZ) and not any(s in fn for s in AUTHZ_SKIP):
            return True
    return False

def _is_method_eq_guard(src, if_node):
    # if <x>.Method == Y  — but only when Y is a PROTOCOL method,
    # not an HTTP transport verb (those are routing/CORS, not RBAC).
    cond = if_node.child_by_field_name("condition")
    if cond is None:
        return False
    t = _txt(src, cond)
    if ".Method" not in t or "==" not in t:
        return False
    if any(v in t for v in HTTP_VERBS):
        return False
    return True

def analyze(path):
    src = open(path, "rb").read()
    root = _P.parse(src).root_node
    findings = []
    for n in _walk(root):
        if n.type != "if_statement" or not _is_method_eq_guard(src, n):
            continue
        cons = n.child_by_field_name("consequence")
        if cons is None or not _has_authz(src, cons):
            continue
        parent = n.parent
        if parent is None:
            continue
        sibs = parent.children
        try:
            idx = sibs.index(n)
        except ValueError:
            continue
        for later in sibs[idx + 1:]:
            hit = None
            for call, fn in _calls(src, later):
                if any(s in fn for s in SINK):
                    hit = (call, fn); break
            if hit:
                call, fn = hit
                findings.append({
                    "gate_line": n.start_point[0] + 1,
                    "sink_line": call.start_point[0] + 1,
                    "sink": fn.strip()[:48],
                })
                break
    return findings

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: a6_ast.py <file.go>"); sys.exit(2)
    fs = analyze(sys.argv[1])
    for f in fs:
        print(f"[A6-ast] method-scoped authz gate @ L{f['gate_line']} "
              f"(authz inside gate) -> ungated sink @ L{f['sink_line']}: {f['sink']}")
    print(f"--- {len(fs)} finding(s) in {sys.argv[1]}")
    sys.exit(1 if fs else 0)