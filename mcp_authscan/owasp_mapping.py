"""OWASP MCP Top 10 mapping for mcp-authscan findings.

Built against the OWASP MCP Top 10, 2025 edition, as published at
owasp.org/projects/mcp-top-10. That page names MCP06 "Prompt Injection
via Contextual Payloads"; the older www-project page still calls it "Intent Flow
Subversion". The name recorded here is the one on the project page, and
MAPPING_VERSION identifies which revision this table was built against.
"""

MAPPING_VERSION = "2026.11.02.1"

CATEGORIES = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
            "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Prompt Injection via Contextual Payloads",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
            "MCP10": "Context Injection & Over-Sharing",
}

# One primary category per rule, so a finding is filed under one heading.
RULE_CATEGORY = {
    "OAuth-1": "MCP07",   # issuer identity
    "OAuth-2": "MCP07",   # resource binding
    "OAuth-3": "MCP01",   # token endpoint Cache-Control
    "OAuth-4": "MCP01",   # token-cors
    "OAuth-5": "MCP01",   # jwks-keys
    "OAuth-6": "MCP07",   # password-grant
    "OAuth-7": "MCP07",   # pkce-s256
    "OAuth-8": "MCP07",   # redirect-uri-exact
    "OAuth-9": "MCP07",   # client-auth
    "OAuth-10": "MCP02",  # cross-tenant
    "OAuth-11": "MCP01",  # token-audience
    "potential_unauthenticated_sensitive_data": "MCP07",
    "cors": "MCP07",
    "ZERO-AUTH": "MCP07",
    "MCPC-1": "MCP03",  # directive-like content in metadata
    "MCPC-2": "MCP10",  # resource or metadata names a private path
}

UNTESTED = {
        "MCP03": "Content is read and directive-like metadata is reported as a finding; a clean read demonstrates no property, so the category carries no verdict.",
    "MCP04": "Needs package, lockfile and provenance inspection; a running endpoint cannot show it.",
    "MCP05": "Out of scope by policy. mcp-authscan checks preconditions and does not attempt execution.",
    "MCP06": "Needs payload and context analysis rather than an HTTP probe.",
    "MCP08": "Needs request-level telemetry from the server, which a prober cannot see.",
    "MCP09": "Needs network discovery and inventory; a target is supplied, never found.",
        "MCP10": "Resource and prompt content is read and private paths are reported as a finding; a clean read demonstrates no property, so the category carries no verdict.",
}

PARTIAL = {
    "MCP02": "Only cross-tenant isolation, and only when MCPAUTHSCAN_CROSS_TENANT=1 is set. A default run leaves it untested.",
}


def category_for(rule):
    if not rule:
        return None
    return RULE_CATEGORY.get(rule)


def tag(rule):
    cid = category_for(rule)
    if cid is None:
        return "unmapped"
    return "%s %s" % (cid, CATEGORIES[cid])


def coverage_rows():
    rows = []
    for cid in sorted(CATEGORIES):
        if cid in PARTIAL:
            rows.append((cid, CATEGORIES[cid], "partial", PARTIAL[cid]))
        elif cid in UNTESTED:
            rows.append((cid, CATEGORIES[cid], "untested", UNTESTED[cid]))
        elif cid in set(RULE_CATEGORY.values()):
            rows.append((cid, CATEGORIES[cid], "covered", ""))
        else:
            rows.append((cid, CATEGORIES[cid], "no-probe", "No rule in this tool maps here, so no verdict."))
    return rows


def owasp_block(payload):
    out = ["OWASP MCP TOP 10 (mapping %s)" % MAPPING_VERSION]
    findings = []
    if isinstance(payload, dict):
        findings = payload.get("findings") or []
    if findings:
        for f in findings:
            if isinstance(f, dict):
                out.append("  %-12s %-10s %s" % (f.get("rule") or "-", f.get("severity") or "-", tag(f.get("rule"))))
    else:
        out.append("  no findings in this run")
    covered = [c for c, n, st, r in coverage_rows() if st == "covered"]
    if covered:
        out.append("  covered: %s" % ", ".join(covered))
    for cid, name, state, reason in coverage_rows():
        if state in ("untested", "partial", "no-probe"):
            out.append("  %s: %s %s. %s" % (state, cid, name, reason))
    return "\n".join(out)


def sarif_rules(rules):
    out = []
    for r in rules:
        t = tag(r.get("id") or r.get("name") or "")
        if not t or t == "unmapped":
            out.append(r)
            continue
        r = dict(r)
        props = dict(r.get("properties") or {})
        props["owasp"] = t
        props["owaspMapping"] = MAPPING_VERSION
        r["properties"] = props
        out.append(r)
    return out
