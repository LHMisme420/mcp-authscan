"""Data-driven report generation from OAuth probe records."""

PASS_EVIDENCE = {
    "issuer-identity": "authorization server metadata names its own issuer",
    "resource-binding": "resource metadata binds to the scanned MCP endpoint",
    "token-cache-control": "token endpoint responses are marked no-store",
    "token-cors": "token endpoint 2xx response did not let the tested origin read it (no Access-Control-Allow-Origin header)",
    "jwks-keys": "signing keys are asymmetric",
    "password-grant": "password grant is not supported",
    "client-auth": "client authentication is enforced before grant validation",
}

def _pass_evidence(r):
    """PASS sentence for one record; token-cors names any other origin the response allowed."""
    if r.name == "token-cors":
        acao = (r.headers_observed or {}).get("access-control-allow-origin", "")
        if acao:
            return ("token endpoint 2xx response did not let the tested origin read it "
                    "(Access-Control-Allow-Origin named %s)" % acao)
    return PASS_EVIDENCE.get(r.name, r.name)

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
    not_impl = [r for r in records if r.status == "NOT_IMPLEMENTED"]

    # PASSED: show with evidence from PASS_EVIDENCE mapping
    if passed:
        evidence = "; ".join(_pass_evidence(r) for r in passed)
        lines.append(f"PASSED ({len(passed)}): {evidence}")

    # EXCLUDED: never sent (prerequisite not met)
    if excluded:
        names = ", ".join(r.name for r in excluded)
        lines.append(f"EXCLUDED ({len(excluded)}, prerequisite missing, never sent): {names}")

    # NOT_IMPLEMENTED: the probe is not built yet; nothing was sent, the target blocked nothing
    if not_impl:
        names = ", ".join(r.name for r in not_impl)
        lines.append(f"NOT IMPLEMENTED ({len(not_impl)}, probe not yet built, never sent): {names}")

    # NOT_OBSERVED: inconclusive; each probe's reason on its own line
    if not_obs:
        lines.append(f"NOT OBSERVED ({len(not_obs)}, inconclusive):")
        for r in not_obs:
            lines.append(f"  {r.name}: {r.detail or r.limitation or '(no reason recorded)'}")

    # FAILED: actual findings
    if failed:
        names = ", ".join(r.name for r in failed)
        lines.append(f"FINDINGS ({len(failed)}): {names}")

    return lines
