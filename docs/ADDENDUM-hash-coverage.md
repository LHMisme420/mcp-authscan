# Addendum: what report_hash covers

2026-10-31, Leroy H. Mason

This addendum records a change to how mcp-authscan computes report_hash. It does not alter any verdict, finding, count, coverage figure or exit code in the reports it refers to.

## Before

report_hash was taken over the whole report payload, including each finding's evidence and remediation text.

## From hash scheme verdict-v2

report_hash is taken over an explicit set of structural keys: target, scan mode, probe set version, hash scheme, counts, coverage, scope, exit contract, exit condition, exit code, fail-on and authorisation, plus each finding's severity, rule, title and location. Each report lists the keys it covered in hash_covers.

## Why

Evidence text can contain values a server generates per run, so under the earlier scheme the digest could differ between two runs over identical evidence.

## What this means for comparison

A hash is comparable within one scheme only. A report issued before this change and a re-run of the same target with current code will carry different hashes for the same evidence. That difference is the coverage of the digest, not a change in result.

## Reports issued under the earlier scheme

- app.twigl.it/mcp, report hash ba2d40ce, tool 1.1.8 (b303861)
- p23ta8.fsmcp.com, report hash b35df9bb, tool 1.1.8 (bcb4d5a), exit contract 2026.10.31.1, probe set 2026.10.31.4

## Not affected by this change

The VATA dashboard PDF content hash (schema version 2, computed over canonical_report of a workspace export, documented in docs/report-hash-verification.md) is a separate scheme over a different artifact. It is unchanged by verdict-v2 and is verified with its own instructions.
