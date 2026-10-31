# Exit Codes - Verified Behavior

## Code Grouping

Contract: 2026.10.31.1. Every report stamps the contract id, the condition that fired and the resulting code, and all three sit inside the report hash, so two reports cannot share a hash while disagreeing about why they exited.

Precondition aborts (no probes run):
- Exit 2: Arguments or setup error
- Exit 3: Target validation failed, including private IP DNS rebinding protection, or a target that is neither an http(s) URL nor a readable source directory. One refusal line on stderr; no report produced.
- Exit 4: Scan error. An unhandled exception, an accounting invariant violation, or a target that is not an MCP server.
- Exit 6: Egress refusal. The request was refused before it left because the host was outside the authorized set.

Outcome codes (probes executed):
- Exit 1: A finding at or above --fail-on. Takes precedence over 5.
- Exit 5: Either zero testable probes on a live scan, or no finding at or above --fail-on and at least one probe ran and could not observe its property (NOT_OBSERVED). Incomplete coverage is an exit code, and it is also named in the Incomplete assessment line and the Coverage line.
- Exit 0: No finding at or above --fail-on, and no NOT_OBSERVED. Coverage counts PASS plus FAIL over in-scope probes, with EXCLUDED probes out of the denominator because each names the prerequisite that was absent.

Conditions recorded with the code: zero_testable_probes, finding_at_or_above_THRESHOLD, not_observed_present, clean.

## Verified Test Cases

| Code | Condition | Evidence |
|------|-----------|----------|
| 3 | Private IP without --allow-private | `[!] Target validation failed: Target localhost resolves to private IP 127.0.0.1 (DNS rebinding protection)` |
| 3 | Target that is neither an existing path nor a URL with a scheme (`://`), e.g. `example.com:443`, `example.com/mcp`, `localhost`, `nosuchdir` | `[!] Target validation failed: Target is neither an existing path nor a URL with a scheme. For a live endpoint use https://host/path. For source mode, pass a path that exists.` (stdout empty). An existing directory with no source files keeps `[!] Refused: no files examined in <dir>; no report produced` |
| 4 | Exception in scan_live_server | `[!] Internal scan error: NameError: name 'broken_function' is not defined` |
| 4 | Accounting invariant violated (harness bumps passed by 1), with or without findings | `[!] ACCOUNTING ERROR: 8 verdicts (expected 7 attempted)`; stdout empty |
| 5 | 401 on /mcp, no discovery metadata | `[!] OAuth detected (HTTP 401) but discovery chain failed. Cannot complete scan.`; stdout empty |
| 0 | Fixture where every in-scope probe passed or was EXCLUDED with its prerequisite named | Coverage reads PASS plus FAIL over in-scope probes; header prints condition clean, exit code 0 |
| 1 | Fixture with a HIGH finding at --fail-on high | Header prints contract 2026.10.31.1, condition finding_at_or_above_high, exit code 1; measured 2026-10-31 |
| 5 | Fixture where a probe ran and could not observe its property, with no finding at or above --fail-on | Incomplete assessment line names the probe; header prints condition not_observed_present, exit code 5; measured 2026-10-31 |

## Exit 5 in Detail: Incomplete Assessment

Superseded twice. e5d56b8 (2026-10-29) removed the coverage rule described below, so an incomplete assessment stopped exiting 5. Contract 2026.10.31.1 (2026-10-31) reinstated exit 5 for a narrower case: no finding at or above --fail-on, and at least one probe that ran and could not observe its property. The run below stays here as a record of the earlier rule.

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

- Corrected 2026-10-31: --json emits JSON. The earlier entry saying it printed stderr was wrong. JSON output carries exit_contract, exit_condition, exit_code and fail_on.


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

