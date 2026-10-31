#!/usr/bin/env python3
"""Fill docs/ASSESSMENT_TEMPLATE.md from an mcp-authscan JSON report plus an engagement file."""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

TOKEN = re.compile(r"\{\{([A-Z0-9_]+)\}\}")
SEVERITIES = ["critical", "high", "medium", "low", "info"]


def load(path, label):
    p = Path(path).expanduser()
    if not p.is_file():
        sys.exit("%s not found: %s" % (label, p))
    try:
        with p.open() as fh:
            return json.load(fh)
    except ValueError as exc:
        sys.exit("%s is not valid JSON: %s" % (label, exc))


def pick(data, *names, default=None):
    for name in names:
        value = data.get(name) if isinstance(data, dict) else None
        if value not in (None, "", [], {}):
            return value
    return default


def findings_of(report):
    return pick(report, "findings", "results", default=[]) or []


def probes_of(report):
    return pick(report, "probes", "probe_results", "checks", default=[]) or []


def severity_line(findings):
    counts = Counter(str(pick(f, "severity", default="unknown")).lower() for f in findings)
    return ", ".join("%s %d" % (s, counts.get(s, 0)) for s in SEVERITIES)


def substitute(text, mapping):
    def repl(match):
        key = match.group(1)
        value = mapping.get(key)
        if value:
            return str(value)
        return "REQUIRES INPUT: " + key
    return TOKEN.sub(repl, text)


def scalar_map(engagement, report):
    mapping = {}
    for key, value in engagement.items():
        if isinstance(value, list):
            value = "\n".join("- " + str(item) for item in value)
        mapping[key.upper()] = "" if value is None else str(value)
    mapping["TOOL_VERSION"] = str(pick(report, "tool_version", "version", default=""))
    mapping["PROBE_SET_VERSION"] = str(pick(report, "probe_set_version", "probe_set", default=""))
    mapping["START_UTC"] = str(pick(report, "start", "started_at", "start_time", default=""))
    mapping["END_UTC"] = str(pick(report, "end", "finished_at", "end_time", default=""))
    mapping["HASH"] = str(pick(report, "hash", "content_hash", default=""))
    return mapping


def render_probes(template_lines, cov_start, probes):
    return [
        substitute(template_lines[cov_start], {
            "PROBE": pick(p, "probe", "name", "id", default=""),
            "VERDICT": pick(p, "verdict", "status", "result", default=""),
            "ENDPOINT": pick(p, "endpoint", "target", "url", default=""),
            "NOTE": pick(p, "note", "prerequisite", "reason", default="-"),
        })
        for p in probes
    ]


def render_findings(template_lines, start, end, findings):
    block = "\n".join(template_lines[start:end + 1])
    rendered = []
    for i, item in enumerate(findings, start=1):
        rendered.append(substitute(block, {
            "FINDING_ID": pick(item, "id", "rule_id", default="F%02d" % i),
            "TITLE": pick(item, "title", "name", "rule", default=""),
            "SEVERITY": pick(item, "severity", default=""),
            "RULE": pick(item, "rule", "rule_id", default=""),
            "ENDPOINT": pick(item, "endpoint", "target", "url", default=""),
            "OBSERVED": pick(item, "observed", "description", "detail", default=""),
            "REDACTED_REQUEST_RESPONSE": pick(item, "evidence", "request", "response", default=""),
            "ARCHITECTURE_IMPACT": pick(item, "architecture_impact", "impact", "interpretation", default=""),
            "REMEDIATION": pick(item, "remediation", "fix", "snippet", default=""),
            "RETEST_CRITERIA": pick(item, "retest_criteria", "retest", default=""),
        }))
    return rendered


def build(template, report, engagement):
    lines = template.split("\n")
    findings = findings_of(report)
    probes = probes_of(report)
    cov = next((i for i, l in enumerate(lines) if l.startswith("| {{PROBE}}")), None)
    fstart = next((i for i, l in enumerate(lines) if l.startswith("### {{FINDING_ID}}")), None)
    fend = next((i for i, l in enumerate(lines) if l.startswith("- Retest criteria:")), None)
    if cov is None or fstart is None or fend is None:
        sys.exit("template is missing its coverage row or findings block")
    body = (lines[:cov] + render_probes(lines, cov, probes) + lines[cov + 1:fstart]
            + "\n\n".join(render_findings(lines, fstart, fend, findings)).split("\n")
            + lines[fend + 1:])
    text = substitute("\n".join(body), scalar_map(engagement, report))
    return "\n".join(
        "Findings by severity: " + severity_line(findings)
        if line.startswith("Findings by severity:") else line
        for line in text.split("\n"))


def main():
    ap = argparse.ArgumentParser(description="Build an assessment from a scan report.")
    ap.add_argument("report")
    ap.add_argument("engagement")
    ap.add_argument("--template", default="docs/ASSESSMENT_TEMPLATE.md")
    ap.add_argument("--out")
    ap.add_argument("--inspect", action="store_true")
    args = ap.parse_args()
    report = load(args.report, "report")
    if args.inspect:
        keys = sorted(report.keys()) if isinstance(report, dict) else sorted(report[0].keys()) if report else []
        print("top level keys:", keys)
        for item in findings_of(report)[:1]:
            print("finding keys:", sorted(item.keys()))
        for item in probes_of(report)[:1]:
            print("probe keys:", sorted(item.keys()))
        return
    engagement = load(args.engagement, "engagement")
    template_path = Path(args.template).expanduser()
    if not template_path.is_file():
        sys.exit("template not found: %s" % template_path)
    text = build(template_path.read_text(), report, engagement)
    out = Path(args.out).expanduser() if args.out else Path("docs/assessments") / (
        str(pick(engagement, "assessment_id", default="assessment")) + ".md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text)
    print("wrote %s" % out)
    print("unfilled fields: %d" % text.count("REQUIRES INPUT:"))


if __name__ == "__main__":
    main()
