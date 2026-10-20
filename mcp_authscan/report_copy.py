"""
Data-driven report generation from OAuth probe records.
Builds summaries from actual measurements, not templates.
"""

# Mapping from probe names to human-readable verdict explanations
PASS_EVIDENCE = {
    "issuer-identity": "Issuer identity bound to OAuth server origin",
    "resource-binding": "Resource endpoint bound to OAuth server config",
    "token-cache-control": "Token endpoint enforces Cache-Control: no-store",
    "token-cors": "Token endpoint CORS configuration observed",
    "jwks-keys": "JWKS endpoint returns valid cryptographic keys",
    "password-grant": "Password grant type correctly unsupported",
    "pkce-s256": "PKCE S256 enforcement verified (registered client only)",
    "redirect-uri-exact": "Redirect URI exact-match validated",
    "client-auth": "Client authentication required (invalid_client confirms enforcement)",
}

OBSERVATION_TEXT = {
    "token-cors": "Token endpoint CORS configuration: impact depends on authentication enforcement",
}

NOT_OBSERVED_REASON = {
    "pkce-s256": "Requires registered client and authorization flow",
    "redirect-uri-exact": "Redirect_uri validation tested via authorization endpoint",
}


def check_counts(oauth_records):
    """
    Verify probe accounting: attempted == passed + failed + not_observed + observed.
    Raises AssertionError if accounting is wrong.
    Returns (passed_count, failed_count, not_observed_count, observed_count).
    """
    if not oauth_records:
        return 0, 0, 0, 0

    passed = sum(1 for r in oauth_records if r.verdict == "PASS")
    failed = sum(1 for r in oauth_records if r.verdict == "FAIL")
    not_observed = sum(1 for r in oauth_records if r.verdict == "NOT_OBSERVED")
    observed = sum(1 for r in oauth_records if r.verdict == "OBSERVATION")

    total_attempted = len(oauth_records)
    total_accounted = passed + failed + not_observed + observed

    assert total_attempted == total_accounted, (
        f"Probe accounting mismatch: attempted={total_attempted}, "
        f"passed={passed}, failed={failed}, not_observed={not_observed}, "
        f"observed={observed}, total accounted={total_accounted}"
    )

    return passed, failed, not_observed, observed


def render_summary(oauth_records):
    """
    Build PROBE RESULTS SUMMARY from actual probe record verdicts.
    Returns list of text lines suitable for report output.
    No misleading prose; every verdict derived from actual measurements.
    """
    if not oauth_records:
        return ["(no probes run)"]

    # Verify accounting first
    passed, failed, not_observed, observed = check_counts(oauth_records)

    lines = []

    # PASSED probes with their specific findings
    if passed > 0:
        passed_probes = [r for r in oauth_records if r.verdict == "PASS"]
        probe_list = ", ".join([r.probe_name for r in passed_probes])
        lines.append(f"PASSED ({passed} probes): {probe_list}")

    # OBSERVATION probes (like token-cors) with their impact
    if observed > 0:
        observed_probes = [r for r in oauth_records if r.verdict == "OBSERVATION"]
        for probe in observed_probes:
            lines.append(f"OBSERVED ({probe.probe_name}): {probe.evidence}")

    # NOT_OBSERVED probes with reason why
    if not_observed > 0:
        not_obs_probes = [r for r in oauth_records if r.verdict == "NOT_OBSERVED"]
        probe_list = ", ".join([r.probe_name for r in not_obs_probes])
        lines.append(f"NOT OBSERVED ({not_observed} probes): {probe_list}")

    # FAIL findings (actual vulnerabilities)
    if failed > 0:
        failed_probes = [r for r in oauth_records if r.verdict == "FAIL"]
        probe_list = ", ".join([r.probe_name for r in failed_probes])
        lines.append(f"FINDINGS ({failed} probes): {probe_list}")

    return lines


def render_assessed(results):
    """
    Render a one-line assessment of what was tested.
    Example: "Assessed: authorization server properties"
    """
    if not results:
        return "Assessed: (no probes run)"

    # Count the properties tested
    passed, failed, not_observed, observed = check_counts(results)
    total_tested = passed + failed + observed  # OBSERVATION counts as tested

    return f"Assessed: authorization server properties ({total_tested} properties tested)"
