import pathlib
import sys
from mcp_authscan.owasp_mapping import coverage_rows, MAPPING_VERSION, RULE_CATEGORY, tag

def rule_key(r):
    tail = str(r).split("-")[-1]
    return (0, int(tail)) if tail.isdigit() else (1, str(r))

def render():
    out = ["# OWASP MCP Top 10 coverage", "",
           "Mapping " + MAPPING_VERSION + ".",
           "A category is covered only when a probe positively demonstrated it.", "",
           "| Category | State | Probes | Backing, or why not |",
           "| --- | --- | --- | --- |"]
    for cid, name, state, reason in coverage_rows():
        rules = sorted((r for r in RULE_CATEGORY if str(tag(r)).startswith(cid)), key=rule_key)
        out.append("| %s %s | %s | %s | %s |" % (cid, name, state, ", ".join(rules) or "-", reason or "-"))
    return "\n".join(out) + "\n"

if sys.argv[0].endswith("render_coverage.py"):
    pathlib.Path("docs/owasp-coverage.md").write_text(render())
    print("wrote docs/owasp-coverage.md")
