---
name: Findings durability approval
description: Owner-approved scope for preserving SQLite findings across replacement deployments.
---

## Current preservation decision

The owner's latest choice is: **"Preserve findings and wait for recovery preparation (recommended)"**.
This supersedes the earlier acceptance of a local-only publishing shortcut below.

**Why:** After the PostgreSQL-backed startup failed, the owner chose preservation
over preparing local-only startup with possible findings loss.

**How to apply:** Leave the current live deployment unchanged while recovery is
prepared. Do not switch to local-only storage to bypass the startup guard, seed
from a new empty database, or publish before the production schema and a verified
live snapshot are ready. Publication still requires separate approval.

## Earlier release investigation constraint

The owner's instruction is: **"Leave backups disabled."**

**Why:** The user explicitly required this while asking to diagnose why the
updated website is not being served in production.

**How to apply:** Do not activate, seed, or run backups as part of publishing
diagnostics. Prior approval of the backup design does not override this
instruction. If preparing a backup-disabled release, distinguish local-only
SQLite from durable storage and explain the replacement-deployment data risk.

Keep SQLite and use the existing PostgreSQL database for private full recovery
snapshots. Do not replace SQLite with PostgreSQL tables without separate owner
approval.
The owner previously chose the fastest local-only startup preparation with
recurring backups off, accepting that existing findings may not carry over and
future findings may be lost when a deployment is replaced. This supersedes the
earlier preservation-first choice only for that startup preparation; it is not
the current publishing authorization.

**Why:** The owner explicitly approved “SQLite with PostgreSQL backups” rather
than a full migration. The workspace database is not evidence of live findings.
After first selecting “Preserve existing findings first,” the owner explicitly
said “lets do the fastest ok” in response to the explained local-only option
and its data-loss consequences.

**How to apply:** The historical local-only exception must not override the current
preservation decision above. Do not weaken the application's default durability
requirement or claim
data preservation or active backups. This acceptance does not authorize seeding
production from workspace findings, reassigning organization ownership, or a
database migration. If durable recovery is resumed, require a verified live
export and matching account identities before cutover. A rehearsal is not
verification of an actual live publish.
