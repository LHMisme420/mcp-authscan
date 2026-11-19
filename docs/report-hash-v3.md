# Single-scan report integrity: schema version 3

Both CLI and single-scan web exports call `mcp_authscan.report_verify.compute`.
The scheme label remains `verdict-v3` as requested, with an explicit
`schema_version: 3` discriminator. Earlier reports bearing that same scheme name
but lacking schema version 3 (releases 1.1.21 to 1.1.24) are **not** reinterpreted
or rewritten as schema 3. From 1.1.25 they are verified with **their own**
algorithm, reproduced verbatim from the 1.1.24 verifier
(`report_verify.compute_legacy`), so a reader no longer needs the original
release. They never authenticate, because that format was never signed.
`python -m mcp_authscan.report_verify REPORT.json` checks either format.

## Covered content

Exactly these top-level keys: `target`, `status`, `total_checks`, `findings_count`,
`probe_set_version`, `coverage`, `severity_counts`, `findings`.

Every finding contains exactly `server_name`, `rule`, `vector_type`, `severity`,
`severity_basis`, `endpoint`, `description`, `remediation`. Missing optional
finding values are explicit nulls. Findings are sorted by their canonical JSON
bytes; duplicates are preserved. Severity counts include zero-valued CRITICAL,
HIGH, MEDIUM, LOW and INFO buckets, and any additional recorded severity.

```python
hashlib.sha256(json.dumps(
    canonical_report, sort_keys=True, separators=(',', ':'),
    ensure_ascii=True, allow_nan=False,
).encode('utf-8')).hexdigest()
```

Timestamps, authorization/session identifiers, raw response headers and varying
response evidence are outside this projection. The checksum binds the complete
covered finding descriptions and remediation, not the raw HTTP evidence. It
does not prove authorship, authenticity or execution coverage.

## Web exports

In Recent scans use the single-scan **PDF** or **JSON** link:

* `/api/reports/pdf?scan_id=ID&format=pdf`
* `/api/reports/pdf?scan_id=ID&format=json`

These retain existing authentication, organization filtering and writer-readiness
guards. The full canonical snapshot is saved atomically with scan completion,
never capped at 1,000 findings. Export uses a read-only transaction and rechecks
the saved digest. Missing legacy evidence returns 409
`REPORT_NOT_REPRODUCIBLE`; a mismatched snapshot returns 409
`REPORT_INTEGRITY_FAILED`. No history is backfilled or assigned fabricated
coverage.

The existing organization-wide summary remains a separate, legacy schema-2
document. Its hash must not be compared with a single scan. It retains its
existing 1,000-detail limit and disclosures.

The legacy web check engine and CLI execute different checks. Their hashes can
only match for the **same recorded canonical scan**, not two independently
executed scans with different findings or probe versions. New web snapshots
identify the actual web source fingerprint and explicitly record coverage as
null because that engine does not track execution prerequisites. A null is
not 100% coverage and is not a passing verdict.

The additive `scan_report_snapshots` table is created by the existing schema
initializer for new scan snapshots. This change does not reset or reseed data.
No production schema operation is performed during workspace verification.
