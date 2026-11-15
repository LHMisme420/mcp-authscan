"""Single-scan web exports using exactly the CLI's schema-3 hash computation."""
from io import BytesIO
from xml.sax.saxutils import escape
import json

from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

from .report_verify import (
    HASH_SCHEME, SCHEMA_VERSION, canonical_report, compute, serialize,
    severity_counts,
)

SERIALIZATION = (
    "json.dumps(canonical_report, sort_keys=True, separators=(',', ':'), "
    "ensure_ascii=True, allow_nan=False).encode('utf-8')"
)


def envelope(payload):
    canonical = canonical_report(payload, payload["findings"])
    digest, covered = compute(canonical, canonical["findings"])
    return {
        **canonical, "schema_version": SCHEMA_VERSION, "hash_scheme": HASH_SCHEME,
        "canonical_report": canonical, "report_hash": digest, "content_hash": digest,
        "hash_algorithm": "SHA-256", "serialization": SERIALIZATION,
        "hash_covers": covered,
    }


def save_snapshot(conn, org_id, scan_id, payload):
    report = envelope(payload)
    conn.execute(
        '''INSERT INTO scan_report_snapshots
           (scan_id,org_id,canonical_json,report_hash) VALUES (?,?,?,?)''',
        (scan_id, org_id, serialize(report["canonical_report"]).decode("utf-8"),
         report["report_hash"]),
    )


def load_snapshot(conn, org_id, scan_id):
    row = conn.execute(
        '''SELECT r.canonical_json,r.report_hash FROM scan_report_snapshots r
           JOIN scan_runs s ON s.id=r.scan_id AND s.org_id=r.org_id
           WHERE r.org_id=? AND r.scan_id=?''', (org_id, scan_id),
    ).fetchone()
    if row is None:
        return None
    report = envelope(json.loads(row[0]))
    if report["report_hash"] != row[1]:
        raise ValueError("Stored report does not match its hash")
    return report


def checks_payload(target, checks, probe_set_version):
    findings = [{
        "server_name": target, "rule": check.name, "vector_type": check.name,
        "severity": check.risk_level.value, "severity_basis": check.severity_basis,
        "endpoint": check.endpoint, "description": check.description,
        "remediation": check.remediation,
    } for check in checks if not check.passed]
    return {
        "target": target, "status": "completed", "total_checks": len(checks),
        "findings_count": len(findings), "probe_set_version": probe_set_version,
        # The legacy web engine does not track execution prerequisites or
        # inconclusive checks. Null is honest; do not fabricate 100% coverage.
        "coverage": None, "severity_counts": severity_counts(findings),
        "findings": findings,
    }


def pdf(report, workspace_name=None):
    output = BytesIO()
    styles = getSampleStyleSheet()
    text = lambda value: escape(str(value))
    canonical = report["canonical_report"]
    story = [
        Paragraph("MCP AuthScan — Single-Scan Report", styles["Title"]),
        Paragraph("Workspace: " + text(workspace_name or "Security workspace"), styles["BodyText"]),
        Paragraph("Report integrity — schema version 3 (verdict-v3)", styles["Heading2"]),
        Paragraph("Target: " + text(canonical["target"]), styles["BodyText"]),
        Paragraph("Status: " + text(canonical["status"]), styles["BodyText"]),
        Paragraph("Probe set: " + text(canonical["probe_set_version"]), styles["BodyText"]),
        Paragraph("Coverage: " + text(canonical["coverage"]) +
                  (" (not recorded; not a claim of complete execution)"
                   if canonical["coverage"] is None else ""), styles["BodyText"]),
        Paragraph("SHA-256: " + report["report_hash"], styles["BodyText"]),
        Paragraph("Verification", styles["Heading2"]),
        Paragraph(
            "Hash only canonical_report from the matching JSON export. It contains "
            "target, status, total_checks, findings_count, probe_set_version, coverage, "
            "severity_counts and the complete findings list. Each finding covers "
            "server_name, rule, vector_type, severity, severity_basis, endpoint, "
            "description and remediation. Finding objects are sorted by their canonical "
            "JSON bytes; duplicates and nulls are preserved.", styles["BodyText"]),
        Paragraph(text(SERIALIZATION) + "; then hashlib.sha256(...).hexdigest().",
                  styles["BodyText"]),
        Paragraph(
            "Excluded: started_at, completed_at, created_at, attested_at, session IDs, "
            "and server-varying headers. No timestamps are included in the hash. "
            "No findings are truncated. This checksum is not a signature, certification, "
            "proof of authenticity, or proof of complete coverage.", styles["BodyText"]),
        Paragraph("Complete finding count: " + str(len(canonical["findings"])), styles["BodyText"]),
    ]
    for finding in canonical["findings"]:
        story += [Spacer(1, 10), Paragraph(text(finding["rule"]), styles["Heading3"])]
        for key, value in finding.items():
            story.append(Paragraph(text(key) + ": " + text(value), styles["BodyText"]))
    SimpleDocTemplate(output, pagesize=letter).build(story)
    return output.getvalue()
