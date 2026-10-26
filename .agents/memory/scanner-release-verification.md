---
name: Scanner release verification
description: Required distinction between repository tests, probe fixtures and report assessment gates.
---

Before deployment, verify the exit-code fixture set on the actual merged tree.
Passing repository-scan tests is not a substitute for probe-fixture verification.
Do not keep a compliance assertion that awards a score without a completed scan.

**Why:** The owner explicitly warned that repository tests cannot reveal a probe
lost during merge resolution and that contradictory scoring tests undermine
confidence in customer reports.

**How to apply:** State exactly which suites ran and which tests CI discovers.
Preserve expected verdicts when fixtures fail; investigate the behavior rather
than weakening expectations to make CI green. Distinguish successful local
checks from incomplete CI prerequisites and from published-release validation.

Release order: pass the exit-code fixtures, consolidate contradictory compliance
scoring expectations, push, publish, then first verify an actual deployed export
contains the report hash. Only afterward compare two deployed exports and
recompute from the deployed JSON data.

**Why:** The owner explicitly requires this sequence; a workspace-only PDF or a
healthy page from an older revision does not validate the shipped report.

**How to apply:** Do not label local hash checks as deployed evidence. Keep
authenticated report access intact and report plainly when no signed-in export
was available to verify.

Bind report hashes to each scan's context, not just a single latest target or
an organization-wide aggregate.

**Why:** The PDF covers an organization's scan history; flattening that history
to one target would misrepresent the scope the owner asked the hash to bind.

**How to apply:** Keep the verification payload reproducible and versioned, and
state its limits. A checksum is not a signature or proof of database durability.
