# Exit Codes - Verified Behavior

## Code Grouping

**Precondition aborts** (no probes run):
- Exit 2: Arguments/setup error
- Exit 3: Target validation failed (including private IP DNS rebinding protection)
- Exit 4: Internal scan error

**Outcome codes** (probes executed):
- Exit 1: Findings detected (FAIL probes above threshold)
- Exit 5: Incomplete assessment (conclusive probes + some EXCLUDED)

**Success**:
- Exit 0: Clean scan (all probes conclusive, no findings)
- Exit 6: (TBD - not yet triggered in testing)

## Verified Test Cases

| Code | Condition | Evidence |
|------|-----------|----------|
| 3 | Private IP without --allow-private | `[!] Target validation failed: Target localhost resolves to private IP 127.0.0.1 (DNS rebinding protection)` |
| 4 | Exception in scan_live_server | `[!] Internal scan error: NameError: name 'broken_function' is not defined` |
| 5 | Mixed verdict assessment | localhost:8765: 4 PASS + 2 FAIL + 3 EXCLUDED = incomplete |

## Exit 5 in Detail: Incomplete Assessment

A single run of localhost:8765 demonstrates all three verdict types:

**Conclusive verdicts (6 probes):**
- PASS: [1] issuer-identity, [3] token-cache-control, [4] token-cors, [5] jwks-keys
- FAIL: [6] password-grant, [9] client-auth

**EXCLUDED (3 probes):**
- [2] resource-binding (prerequisite: oauth-protected-resource metadata)
- [7] pkce-s256 (prerequisite: code_challenge_methods_supported)
- [8] redirect-uri-exact (prerequisite: registration_endpoint)

**Exit code:** 5 (incomplete assessment)  
**Outcome:** Findings exist (2 FAIL), but assessment incomplete (3 probes blocked by missing prerequisites)  
**Note:** If all 9 probes could run with these same 2 FAIL results, exit would be 1, not 5.

## Known Issues

- **--json flag broken**: The `--json` flag outputs stderr text instead of JSON. EXCLUDED probe details cannot be verified from JSON at this time. This requires separate investigation and fix.


## 2026-10-29 05:59 EDT — Exit code proof

Exit code behavior verified against fixture endpoints:

**Rule**: fail_on=HIGH, threshold=1, order={PASS:0, FAIL:1, EXCLUDED:2}
- Finding with severity FAIL (level 1) >= threshold (1) → findings_at_threshold=True → exit 1
- No findings >= threshold → exit 0

**Measured**:
- Clean endpoint (realistic 4xx + no CORS): exit 0 ✓
- Misbehave endpoint (400 + ACAO:*): exit 1 ✓

**Note**: Measurement requires `$? captured before any other command`. Using 
`echo "exit=$?"` directly captures the exit code of mcp-authscan. Piping through 
grep or other commands, or placing echo between the tool and the $? read, 
measures the wrong process exit code.

