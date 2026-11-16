---
name: Compliance report claims
description: Keep the VATA severity score distinct from formal third-party compliance attestations.
---

Describe the VATA severity-based score as an indicator. Do not call it a SOC 2 attestation, certification, or audit opinion.

**Why:** the score is a VATA severity heuristic, not an independent SOC 2 assessment.

**How to apply:** use this distinction in generated reports, dashboard labels, and other compliance-related product wording.

## Optional declaration-check evidence

Keep the optional Boundary declaration-check rows outside the existing
`pdf-recompute-v1` canonical payload. Its supplied graded-row digest is separate.
MATCH means annotation consistency, not demonstrated authorization enforcement.

**Why:** Existing exported reports must still recompute unchanged; observations
made without credentials or tool calls cannot establish access-control enforcement.

**How to apply:** Do not silently widen the old hash or imply its checksum covers
the added section. Wiring a real boundary producer requires its actual digest
contract; rendering a supplied digest alone does not verify it.

## User-required single-scan integrity contract

Use exactly the requested verdict-v3 schema-3 fields and canonical JSON rules
for web/CLI comparisons. Timestamps, session identifiers and varying headers
must not affect the digest. Keep multi-scan organization summaries distinct
from single-scan exports; never silently substitute the latest scan.

**Why:** the user explicitly chose separate single-scan exports to avoid
comparing an organization-history hash with a CLI scan. Legacy evidence must
remain honestly incomplete, not assigned invented coverage or probe versions.

**How to apply:** compare identical recorded scan content, not independent
executions of different scanner engines. A null coverage value is not complete
coverage. State clearly whether parity was demonstrated with synthetic/local
evidence or with a published customer export.
