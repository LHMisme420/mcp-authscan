"""Text rendering. Recomputes counts from probe records and refuses a mismatch."""
from ._common import VALID_STATUSES

FOOTER = "Absence of a finding is not proof of safety."


def recompute(probes):
    counts = {status: 0 for status in VALID_STATUSES}
    for rec in probes:
        status = rec.get("status")
        if status not in VALID_STATUSES:
            raise RuntimeError("probe %r has illegal status %r"
                               % (rec.get("probe_id"), status))
        counts[status] += 1
    counts["in_scope"] = len(probes)
    counts["attempted"] = counts["in_scope"] - counts["EXCLUDED"]
    return counts


def check_counts(payload, probes):
    stated = payload.get("counts") or {}
    derived = recompute(probes)
    for key, value in derived.items():
        if stated.get(key) != value:
            raise RuntimeError(
                "counts disagree: %s stated %r, records say %r"
                % (key, stated.get(key), value))
    return derived


def rule(char="-", width=72):
    return char * width


def render_text(payload):
    probes = payload.get("probes") or []
    counts = check_counts(payload, probes)
    attempted = counts["attempted"]
    cov = (counts["PASS"] + counts["FAIL"]) / float(attempted) if attempted else 0.0

    lines = []
    add = lines.append

    add("mcp-authscan security review")
    add(rule("="))
    add("Assessed by : %s" % (payload.get("authorization", {}).get("assessor") or "not stated"))
    add("Target      : %s" % (payload.get("target") or "not stated"))
    add("Scan date   : %s" % (payload.get("scan_date") or "not stated"))
    add("Tool        : %s (probe set %s)" % (
        payload.get("tool_version") or "unknown",
        payload.get("probe_set_version") or "unknown"))
    add("")
    add("Authorization basis")
    add(rule())
    add(str(payload.get("authorization") or "not stated"))
    add("")
    add("Scope")
    add(rule())
    add(str(payload.get("scope") or "not stated"))
    for item in payload.get("not_tested") or []:
        add("  not tested: %s" % item)
    add("")
    add("Counts")
    add(rule())
    add("in scope   %d" % counts["in_scope"])
    add("attempted  %d" % attempted)
    add("  PASS           %d" % counts["PASS"])
    add("  FAIL           %d" % counts["FAIL"])
    add("  NOT_OBSERVED   %d" % counts["NOT_OBSERVED"])
    add("excluded   %d" % counts["EXCLUDED"])
    add("coverage   %.4f" % cov)
    add("")
    add("Probes")
    add(rule())
    for rec in probes:
        add("%-3s %-12s %-34s %s" % (
            rec.get("probe_id"),
            rec.get("status"),
            (rec.get("name") or "")[:34],
            "http=%s" % rec.get("http_status") if rec.get("http_status") else ""))
        if rec.get("detail"):
            add("    %s" % rec["detail"])
        if rec.get("limitation"):
            add("    limit: %s" % rec["limitation"])
        if rec.get("body_sha256"):
            add("    body sha256: %s" % rec["body_sha256"])
    findings = [r for r in probes if r.get("status") == "FAIL"]
    add("")
    add("Findings")
    add(rule())
    if not findings:
        add("None at the tested properties.")
    for rec in findings:
        add("%s  %s" % ((rec.get("severity") or "UNRATED"), rec.get("name")))
        add("    endpoint: %s" % (rec.get("endpoint") or "not recorded"))
        add("    %s" % (rec.get("detail") or ""))
    add("")
    add(rule("="))
    add("Report hash : %s" % (payload.get("report_hash") or "not computed"))
    add(FOOTER)
    return "\n".join(lines) + "\n"
