#!/usr/bin/env python3
"""
Generate forensic diff between two mcp-authscan reports.
Shows what changed: new findings, resolved findings, probe set version changes.
"""
import json
import sys
import argparse
from datetime import datetime, timezone
import hashlib

def load_report(json_path):
    """Load a JSON report from mcp-authscan."""
    try:
        with open(json_path) as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading report {json_path}: {e}", file=sys.stderr)
        sys.exit(1)

def finding_key(finding):
    """Create a unique key for a finding to detect duplicates across runs."""
    return (
        finding.get("rule"),
        finding.get("file"),
        finding.get("title"),
        finding.get("evidence", "")[:100]  # first 100 chars of evidence
    )

def format_finding(f):
    """Format a finding for display."""
    return f"[{f['severity']}/{f['confidence']}] {f['rule']}: {f['title']}"

def main():
    ap = argparse.ArgumentParser(
        description="Generate forensic diff between two mcp-authscan reports"
    )
    ap.add_argument("before", help="JSON report from initial scan")
    ap.add_argument("after", help="JSON report after remediation")
    ap.add_argument("--output", "-o", help="Save diff to JSON file")
    args = ap.parse_args()

    before = load_report(args.before)
    after = load_report(args.after)

    before_findings = before.get("findings", [])
    after_findings = after.get("findings", [])

    before_keys = {finding_key(f): f for f in before_findings}
    after_keys = {finding_key(f): f for f in after_findings}

    # Calculate differences
    resolved = [before_keys[k] for k in before_keys if k not in after_keys]
    new = [after_keys[k] for k in after_keys if k not in before_keys]
    unchanged = [k for k in before_keys if k in after_keys]

    # Extract metadata
    before_target = before.get("target", "unknown")
    after_target = after.get("target", "unknown")

    before_auth = before.get("authorization", {})
    after_auth = after.get("authorization", {})

    # Generate diff report
    diff_report = {
        "diff_timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "target": after_target,
        "authorization": after_auth,
        "scan_comparison": {
            "before_scan": before.get("target"),
            "after_scan": after.get("target"),
            "before_findings_total": len(before_findings),
            "after_findings_total": len(after_findings),
            "findings_resolved": len(resolved),
            "findings_new": len(new),
            "findings_unchanged": len(unchanged),
        },
        "before": {
            "commit_sha": before.get("commit_sha"),
            "findings_total": len(before_findings),
        },
        "after": {
            "commit_sha": after.get("commit_sha"),
            "findings_total": len(after_findings),
        },
        "resolved_findings": resolved,
        "new_findings": new,
        "impact_summary": {
            "critical_resolved": len([f for f in resolved if f.get("severity") == "CRITICAL"]),
            "critical_new": len([f for f in new if f.get("severity") == "CRITICAL"]),
            "high_resolved": len([f for f in resolved if f.get("severity") == "HIGH"]),
            "high_new": len([f for f in new if f.get("severity") == "HIGH"]),
            "medium_resolved": len([f for f in resolved if f.get("severity") == "MEDIUM"]),
            "medium_new": len([f for f in new if f.get("severity") == "MEDIUM"]),
        }
    }

    # Calculate diff hash
    diff_json = json.dumps(diff_report, sort_keys=True).encode()
    diff_hash = hashlib.sha256(diff_json).hexdigest()
    diff_report["diff_sha256"] = diff_hash

    # Human-readable output
    print("=" * 80)
    print("MCSCAN DIFFERENTIAL REPORT")
    print("=" * 80)
    print(f"\nTarget: {after_target}")
    if after_auth:
        print(f"Authorization: {after_auth.get('authorized_by')} at {after_auth.get('client_name')}")
    print(f"Scan Date: {after_auth.get('scan_date', 'unknown')}")

    print(f"\n{'-' * 80}")
    print("COMPARISON")
    print(f"{'-' * 80}")
    print(f"Before: {len(before_findings)} findings")
    print(f"After:  {len(after_findings)} findings")
    print(f"\nResolved: {len(resolved)} findings")
    print(f"New:      {len(new)} findings")
    print(f"Unchanged: {len(unchanged)} findings")

    if diff_report["impact_summary"]["critical_resolved"] > 0 or diff_report["impact_summary"]["critical_new"] > 0:
        print(f"\nCRITICAL: {diff_report['impact_summary']['critical_resolved']} resolved, "
              f"{diff_report['impact_summary']['critical_new']} new")
    if diff_report["impact_summary"]["high_resolved"] > 0 or diff_report["impact_summary"]["high_new"] > 0:
        print(f"HIGH:     {diff_report['impact_summary']['high_resolved']} resolved, "
              f"{diff_report['impact_summary']['high_new']} new")
    if diff_report["impact_summary"]["medium_resolved"] > 0 or diff_report["impact_summary"]["medium_new"] > 0:
        print(f"MEDIUM:   {diff_report['impact_summary']['medium_resolved']} resolved, "
              f"{diff_report['impact_summary']['medium_new']} new")

    if resolved:
        print(f"\n{'-' * 80}")
        print("RESOLVED FINDINGS")
        print(f"{'-' * 80}")
        for f in resolved:
            print(f"  ✓ {format_finding(f)}")

    if new:
        print(f"\n{'-' * 80}")
        print("NEW FINDINGS")
        print(f"{'-' * 80}")
        for f in new:
            print(f"  ✗ {format_finding(f)}")

    print(f"\n{'-' * 80}")
    print(f"Diff Hash (SHA256): {diff_hash}")
    print("=" * 80)

    # Save JSON if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(diff_report, f, indent=2)
        print(f"\n[+] Diff saved to {args.output}")

    return 0

if __name__ == "__main__":
    sys.exit(main())
