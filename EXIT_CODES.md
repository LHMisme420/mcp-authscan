# Exit Codes - Verified Behavior

| Code | Meaning | Status |
|------|---------|--------|
| 0 | Clean scan (no findings, all probes conclusive) | Pending: needs server with no FAIL probes |
| 1 | Findings detected (FAIL probes above threshold) | Pending: localhost has 2 FAIL, but exit 5 (incomplete) takes precedence |
| 2 | Arguments/setup error | Verified: `mcp-authscan` without target |
| 3 | Target validation failed | Verified: DNS resolution failure |
| 4 | Internal scan error | Verified: NameError in scan_live_server |
| 5 | Incomplete assessment | Verified: localhost:8765 (3 probes EXCLUDED) |
| 6 | Guard refusal (private IP) | Pending: needs localhost without --allow-private |

## Exit 5 - Incomplete Assessment Example

**Test case:** localhost:8765 (minimal OAuth server)

**Result summary:**
- 6 probes with conclusive verdicts: 4 PASS + **2 FAIL**
- 3 probes EXCLUDED (missing prerequisites): resource-binding, pkce-s256, redirect-uri-exact
- **Not a clean scan** – contains findings (password-grant FAIL, client-auth FAIL)
- Exit 5 because assessment is incomplete (not all probes could run)

**Takeaway:** Exit 5 can coexist with findings. Exit code precedence: validation errors (2-4) > findings (1) > incomplete assessment (5).
