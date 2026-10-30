# Exit Codes - Verified Behavior

## Code Grouping

**Precondition aborts** (no probes run):
- Exit 2: Arguments/setup error
- Exit 3: Target validation failed (including private IP DNS rebinding protection), or a target that is neither an http(s) URL nor a readable source directory (nothing examined: no source files read, or no probes attempted). One refusal line naming the target is the last line on stderr; no report of any kind is produced.
- Exit 4: Scan error. This covers three different events: an internal error (an unhandled exception in the scanner; stderr ends with `[!] Internal scan error: ...`), an accounting invariant violation (stderr shows `[!] ACCOUNTING ERROR: ...`) for verdicts not equal to attempted, or attempted + EXCLUDED + NOT_IMPLEMENTED not equal to 9; exits 4 whether or not anything was found), and a target that is not an MCP server (preflight did not verify it and no OAuth surface was found; currently no dedicated `[!]` line, only the preflight progress lines).

**Outcome codes** (probes executed):
- Exit 1: Findings detected (FAIL probes above threshold)
- Exit 5: Any in-scope probe with no verdict (NOT_OBSERVED). EXCLUDED does not count.

**Success**:
- Exit 0: No findings at or above --fail-on, and no in-scope probe left without a verdict.
- Exit 6: Refused to send a request to a host outside the authorized set.

## Verified Test Cases

| Code | Condition | Evidence |
|------|-----------|----------|
| 3 | Private IP without --allow-private | `[!] Target validation failed: Target localhost resolves to private IP 127.0.0.1 (DNS rebinding protection)` |
| 3 | Target neither an http(s) URL nor a readable source directory | `[!] Refused: no files examined in p23ta8.fsmcp.com/mcp; no report produced` (schemeless target treated as a local path; stdout empty) |
| 4 | Exception in scan_live_server | `[!] Internal scan error: NameError: name 'broken_function' is not defined` |
| 4 | Accounting invariant violated (harness bumps passed by 1), with or without findings | `[!] ACCOUNTING ERROR: 8 verdicts (expected 7 attempted)`; stdout empty |
| 5 | Any in-scope probe without a verdict | `[!] OAuth detected (HTTP 401) but discovery chain failed. Cannot complete scan.`; stdout empty |
| 0 | Clean fixture without client credentials: 5 PASS, 2 NOT_OBSERVED, 2 NOT_IMPLEMENTED | `[!] Incomplete assessment: 5 probes reached conclusive verdicts...`; Coverage 5 of 9 (0.56) |

## Exit 5 in Detail: Incomplete Assessment

*Superseded 2026-10-30:* exit 5 now fires on NOT_OBSERVED only; excluded probes print and count but do not gate.

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

**Since 98ddd03 (2026-10-29):** the localhost:8765 run above predates the NOT_IMPLEMENTED label. [7] pkce-s256 and
[8] redirect-uri-exact are not yet built: they are now reported NOT_IMPLEMENTED (never sent), not EXCLUDED, and
carry no prerequisites. The accounting is attempted = PASS + FAIL + NOT_OBSERVED, and
attempted + EXCLUDED + NOT_IMPLEMENTED = 9. Coverage is (PASS + FAIL) / 9, the declared set, so a clean run reads
7/9 (0.78) with both unbuilt probes named. Exit codes are unchanged by this: a clean run still exits 0.

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

