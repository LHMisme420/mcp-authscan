"""Data-driven report generation from OAuth probe records."""

PASS_EVIDENCE = {
    "issuer-identity": "authorization server metadata names its own issuer",
    "resource-binding": "resource metadata binds to the scanned MCP endpoint",
    "token-cache-control": "token endpoint responses are marked no-store",
    "jwks-keys": "signing keys are asymmetric",
    "password-grant": "password grant is not supported",
    "client-auth": "client authentication is enforced before grant validation",
}

def check_counts(records):
    """Verify accounting."""
    if not records:
        return 0, 0, 0, 0
    passed = sum(1 for r in records if r.verdict == "PASS")
    failed = sum(1 for r in records if r.verdict == "FAIL")
    not_obs = sum(1 for r in records if r.verdict == "NOT_OBSERVED")
    obs = sum(1 for r in records if r.verdict == "OBSERVATION")
    return passed, failed, not_obs, obs

def render_summary(records):
    """Build summary from actual probe verdicts with human-readable evidence."""
    if not records:
        return []
    
    lines = []
    passed = [r for r in records if r.verdict == "PASS"]
    obs = [r for r in records if r.verdict == "OBSERVATION"]
    not_obs = [r for r in records if r.verdict == "NOT_OBSERVED"]
    failed = [r for r in records if r.verdict == "FAIL"]
    
    if passed:
        evidence = "; ".join(PASS_EVIDENCE.get(r.probe_name, r.probe_name) for r in passed)
        lines.append(f"PASSED ({len(passed)}): {evidence}")
    
    if obs:
        for r in obs:
            lines.append(f"OBSERVED ({r.probe_name}): {r.evidence}")
    
    if not_obs:
        # Distinguish excluded (never sent) from not_observed (sent, inconclusive)
        excluded = [r for r in not_obs if hasattr(r, 'prerequisite_met') and not r.prerequisite_met]
        inconclusive = [r for r in not_obs if not (hasattr(r, 'prerequisite_met') and not r.prerequisite_met)]

        if excluded:
            names = ", ".join(r.probe_name for r in excluded)
            lines.append(f"EXCLUDED ({len(excluded)}, prerequisite missing, never sent): {names}")

        if inconclusive:
            names = ", ".join(r.probe_name for r in inconclusive)
            lines.append(f"NOT OBSERVED ({len(inconclusive)}): {names}")
    
    if failed:
        names = ", ".join(r.probe_name for r in failed)
        lines.append(f"FINDINGS ({len(failed)}): {names}")
    
    return lines
