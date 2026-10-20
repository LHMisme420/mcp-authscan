"""Report narration. Every sentence is derived from result records.

TOOL_VERSION names the code that executed, not published package metadata.
"""

TOOL_VERSION = "1.1.0"
PROBE_SET_VERSION = "1.1.0"
CONDUCTED_BY = "Leroy H. Mason"
METHOD_NOTE = ("Probe design, scope and findings by Leroy H. Mason. "
               "Code and report generation AI-assisted (Claude, Anthropic).")

PASS_EVIDENCE = {
    "issuer-identity": "authorization server metadata names its own issuer",
    "resource-binding": "resource metadata binds to the scanned MCP endpoint",
    "token-cache-control": "token endpoint responses are marked no-store",
    "jwks-keys": "signing keys are asymmetric",
    "password-grant": "password grant is not supported",
    "client-auth": "client authentication is enforced before grant validation",
}

OBSERVATION_TEXT = {
    "token-cors": "wildcard CORS on token endpoint (authentication enforced)",
}

def check_counts(records, attempted, passed, failed, not_observed):
    """Verify probe counts add up. Raise if accounting fails."""
    by_verdict = {}
    for r in records:
        v = r.verdict
        by_verdict[v] = by_verdict.get(v, 0) + 1
    
    actual_passed = by_verdict.get("PASS", 0)
    actual_not_obs = by_verdict.get("NOT_OBSERVED", 0)
    actual_obs = by_verdict.get("OBSERVATION", 0)
    actual_failed = by_verdict.get("FAIL", 0)
    
    total = actual_passed + actual_failed + actual_not_obs + actual_obs
    if total != attempted:
        raise ValueError(f"Accounting: {total} != {attempted}")
    if actual_passed != passed:
        raise ValueError(f"PASSED: {actual_passed} != {passed}")
    if actual_not_obs != not_observed:
        raise ValueError(f"NOT_OBSERVED: {actual_not_obs} != {not_observed}")

def render_summary(records):
    """Build probe summary from actual records. Never hand-written."""
    passed = [r for r in records if r.verdict == "PASS"]
    observed = [r for r in records if r.verdict == "OBSERVATION"]
    not_obs = [r for r in records if r.verdict == "NOT_OBSERVED"]
    
    lines = []
    lines.append("PROBE RESULTS SUMMARY")
    lines.append("-" * 80)
    lines.append("Assessed: authorization server properties (RFC 8414)")
    
    if passed:
        evidence_list = "; ".join(PASS_EVIDENCE.get(r.probe_name, r.probe_name) for r in passed)
        lines.append(f"PASSED ({len(passed)}): {evidence_list}")
    
    if observed:
        obs_names = ", ".join(f"{r.probe_name} ({OBSERVATION_TEXT.get(r.probe_name, '')})" for r in observed)
        lines.append(f"OBSERVED ({len(observed)}): {obs_names}")
    
    if not_obs:
        not_obs_names = ", ".join(r.probe_name for r in not_obs)
        lines.append(f"NOT OBSERVED ({len(not_obs)}): {not_obs_names} (require registered client or authorization flow)")
    
    lines.append("-" * 80)
    return "\n".join(lines)

