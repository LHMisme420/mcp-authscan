---
name: Findings durability approval
description: Owner-approved scope for preserving SQLite findings across replacement deployments.
---

## Current PostgreSQL durability decision

The owner subsequently said **"dont preserve the findings"**, then clarified
**"Don't switch back to local-only"** and requested initialization from a newly
created SQLite database for PostgreSQL-backed findings storage.
This supersedes the preservation-first and local-only publishing choices below.

**Why:** The owner wants PostgreSQL durability without preserving old findings,
rather than bypassing the startup check with temporary local-only storage.

**How to apply:** Keep PostgreSQL durability. A fresh initial findings snapshot is
authorized, but must target the actual intended production database and must not
overwrite an existing namespace, delete unrelated records, or reassign ownership.
Do not treat workspace DATABASE_URL as production. The owner subsequently said
**"Remove the automatic fresh-initialization at startup. Don't create the schema
during deploy"** and requires a one-time operator seed before publishing. This
supersedes the earlier approval for automatic production initialization.

**Why:** The publishing attempt crash-looped in the automatic SQLite initializer;
the owner explicitly chose manual seeding instead.

**How to apply:** Startup may only validate and restore an existing snapshot.
Keep PostgreSQL durability, confirm production signing-secret availability
without displaying values, and do not publish until the actual production
namespace is seeded. Never seed development and describe it as production.
The owner chose **"Prepare a production SQL import for me to run"** for this
one-time empty seed; execution is an operator action in the production Database
tool, followed by read-only verification before publishing.

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
PostgreSQL decision above. Do not weaken the application's default durability
requirement or claim
data preservation or active backups. This acceptance does not authorize seeding
production from workspace findings, reassigning organization ownership, or a
database migration. If durable recovery is resumed, require a verified live
export and matching account identities before cutover. A rehearsal is not
verification of an actual live publish.
