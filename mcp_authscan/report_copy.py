"""Data-driven report generation from OAuth probe records."""

PASS_EVIDENCE = {
    "issuer-identity": "authorization server metadata names its own issuer",
    "resource-binding": "resource metadata binds to the scanned MCP endpoint",
    "token-cache-control": "token endpoint responses are marked no-store",
    "token-cors": "token endpoint 2xx response did not admit the hostile origin (no Access-Control-Allow-Origin header)",
    "jwks-keys": "signing keys are asymmetric",
    "password-grant": "password grant is not supported",
    "client-auth": "client authentication is enforced before grant validation",
}

def check_counts(records):
    """Verify accounting: return (passed, failed, not_observed, excluded)."""
    if not records:
        return 0, 0, 0, 0
    
    passed = sum(1 for r in records if r.status == "PASS")
    failed = sum(1 for r in records if r.status == "FAIL")
    not_obs = sum(1 for r in records if r.status == "NOT_OBSERVED")
    excluded = sum(1 for r in records if r.status == "EXCLUDED")
    
    return passed, failed, not_obs, excluded

def render_summary(records):
    """Build summary from actual probe verdicts with human-readable evidence."""
    if not records:
        return []

    lines = []
    
    # Group records by status
    passed = [r for r in records if r.status == "PASS"]
    failed = [r for r in records if r.status == "FAIL"]
    not_obs = [r for r in records if r.status == "NOT_OBSERVED"]
    excluded = [r for r in records if r.status == "EXCLUDED"]

    # PASSED: show with evidence from PASS_EVIDENCE mapping
    if passed:
        evidence = "; ".join(PASS_EVIDENCE.get(r.name, r.name) for r in passed)
        lines.append(f"PASSED ({len(passed)}): {evidence}")

    # EXCLUDED: never sent (prerequisite not met)
    if excluded:
        names = ", ".join(r.name for r in excluded)
        lines.append(f"EXCLUDED ({len(excluded)}, prerequisite missing, never sent): {names}")

    # NOT_OBSERVED: sent, but inconclusive
    if not_obs:
        lines.append(f"NOT OBSERVED ({len(not_obs)}, sent, inconclusive):")
        for r in not_obs:
            lines.append(f"  {r.name}: {r.detail or r.limitation or '(no reason recorded)'}")

    # FAILED: actual findings
    if failed:
        names = ", ".join(r.name for r in failed)
        lines.append(f"FINDINGS ({len(failed)}): {names}")

    return lines
