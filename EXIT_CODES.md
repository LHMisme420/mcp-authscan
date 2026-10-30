# Exit Codes - Verified Behavior

## Code Grouping

**Precondition aborts** (no probes run):
- Exit 2: Arguments/setup error
- Exit 3: Target validation failed (including private IP DNS rebinding protection), or a target that is neither an http(s) URL nor a readable source directory (nothing examined: no source files read, or no probes attempted). One refusal line naming the target is the last line on stderr; no report of any kind is produced.
- Exit 4: Scan error. This covers three different events: an internal error (an unhandled exception in the scanner; stderr ends with `[!] Internal scan error: ...`), an accounting invariant violation (stderr shows `[!] ACCOUNTING ERROR: ...`) for verdicts not equal to attempted, or attempted + EXCLUDED + NOT_IMPLEMENTED not equal to 9; exits 4 whether or not anything was found), and a target that is not an MCP server (preflight did not verify it and no OAuth surface was found; currently no dedicated `[!]` line, only the preflight progress lines).

**Outcome codes** (probes executed):
- Exit 1: Findings detected (FAIL probes above threshold)
- Exit 5: Zero testable probes on a live scan: OAuth was detected (HTTP 401) but the RFC 9728 / RFC 8414 discovery chain did not complete, so no probe could run, and nothing was found. Incomplete coverage is never an exit code: it is reported as the `[!] Incomplete assessment` line and the Coverage line.

**Success**:
- Exit 0: No findings at or above --fail-on. Coverage may be incomplete; that is stated in the output, not in the exit code.
- Exit 6: (TBD - not yet triggered in testing)

## Verified Test Cases

| Code | Condition | Evidence |
|------|-----------|----------|
| 3 | Private IP without --allow-private | `[!] Target validation failed: Target localhost resolves to private IP 127.0.0.1 (DNS rebinding protection)` |
| 3 | Target that is neither an existing path nor a URL with a scheme (`://`), e.g. `example.com:443`, `example.com/mcp`, `localhost`, `nosuchdir` | `[!] Target validation failed: Target is neither an existing path nor a URL with a scheme. For a live endpoint use https://host/path. For source mode, pass a path that exists.` (stdout empty). An existing directory with no source files keeps `[!] Refused: no files examined in <dir>; no report produced` |
| 4 | Exception in scan_live_server | `[!] Internal scan error: NameError: name 'broken_function' is not defined` |
| 4 | Accounting invariant violated (harness bumps passed by 1), with or without findings | `[!] ACCOUNTING ERROR: 8 verdicts (expected 7 attempted)`; stdout empty |
| 5 | 401 on /mcp, no discovery metadata | `[!] OAuth detected (HTTP 401) but discovery chain failed. Cannot complete scan.`; stdout empty |
| 0 | Clean fixture without client credentials: 5 PASS, 2 NOT_OBSERVED, 2 NOT_IMPLEMENTED | `[!] Incomplete assessment: 5 probes reached conclusive verdicts...`; Coverage 5 of 9 testable (0.56): nothing EXCLUDED, and NOT_IMPLEMENTED stays in the testable count |

## Exit 5 in Detail: Incomplete Assessment

**Superseded by e5d56b8 (2026-10-29):** the coverage rule described below was removed. An incomplete assessment no longer exits 5; this run would now exit on its two FAIL findings (exit 1 when they are at or above --fail-on), with the incomplete assessment stated in the output. Kept as a historical record.

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
attempted + EXCLUDED + NOT_IMPLEMENTED = 9. Coverage is (PASS + FAIL) / testable, testable = 9 - EXCLUDED; NOT_IMPLEMENTED is
not excluded, so that clean run read 7 of 9 testable (0.78) with both unbuilt probes named. Since 7-8 are built and EXCLUDED
without a client, a clean run reads 7 of 7 testable (1.00) with both named as excluded. Exit codes are unchanged by this: a clean run still exits 0.

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

