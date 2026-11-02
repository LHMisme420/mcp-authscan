import pathlib
import sys
from mcp_authscan.owasp_mapping import coverage_rows, MAPPING_VERSION, RULE_CATEGORY, tag

def rule_key(r):
    tail = str(r).split("-")[-1]
    return (0, int(tail)) if tail.isdigit() else (1, str(r))

def render():
    out = [
        "# OWASP MCP Top 10 coverage",
        "",
        "Mapping " + MAPPING_VERSION + ".",
        "",
        "Which of the ten categories mcp-authscan can decide on a running MCP server, which it can only partly decide, and which it does not test at all.",
        "",
        "A category is covered only when a probe positively demonstrated the property on a live endpoint. A 404, a timeout, a 5xx or an unexpected body is not a pass. A probe that could not run is excluded with its missing prerequisite named, and is counted as neither a pass nor a failure.",
        "",
        "Three things no endpoint prober can settle. It cannot verify a three-party OAuth flow, where the client, the authorization server and the resource are separate parties. It cannot read tool descriptions, prompts or resources, so tool poisoning and context over-sharing sit outside it. It cannot discover a server, only assess one it was handed, so shadow MCP servers are out of reach.",
        "",
        "Every report stamps this mapping version beside the probe-set version, so a report issued under one revision is never quietly read as another.",
        "",
        "| Category | State | Probes | Backing, or why not |",
        "| --- | --- | --- | --- |",
    ]
    for cid, name, state, reason in coverage_rows():
        rules = sorted((r for r in RULE_CATEGORY if str(tag(r)).startswith(cid)), key=rule_key)
        out.append("| %s %s | %s | %s | %s |" % (cid, name, state, ", ".join(rules) or "-", reason or "-"))
    return "\n".join(out) + "\n"

if sys.argv[0].endswith("render_coverage.py"):
    pathlib.Path("docs/owasp-coverage.md").write_text(render())
    print("wrote docs/owasp-coverage.md")
