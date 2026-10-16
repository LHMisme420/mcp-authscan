---
name: SQLite writer deployment handoff
description: Production revision overlap blocks republishing with the exclusive findings writer.
---

Verify a stop-before-start handoff before republishing the PostgreSQL-backed
SQLite writer. A seeded namespace and passing workspace startup tests do not
establish that a replacement production revision can acquire the writer lock.

**Why:** After the first durable release succeeded, the next Autoscale publish
built its image successfully but crash-looped because the existing release kept
the namespace's PostgreSQL advisory writer lock. Production snapshots continued
to advance while the replacement reported “Another findings writer is active.”
The earlier publish-readiness advice missed this revision overlap.

**How to apply:** Explain that the current design requires stopping the old
published instance before starting its replacement. Obtain approval for a brief
maintenance outage and use the documented publishing shutdown flow, then verify
the replacement's readiness in production logs. Check the latest durable
snapshot's checksum before the handoff. A maximum-machine setting is not proof
that the previous revision has stopped. Never steal the lock, terminate database
sessions, reseed, change namespaces, or revert to local-only storage to bypass
the failure. An automatic handoff or direct PostgreSQL findings migration is a
separate architecture change, not an implicit publishing fix.

Do not use the production SQL runner's `pg_locks` count to certify writer release.

**Why:** This runner connects to a read replica (`pg_is_in_recovery()` is true).
Its advisory-lock view does not describe the live primary's writer sessions.

**How to apply:** Check the connection's recovery status before interpreting
session or lock metadata. Zero replica locks are not evidence that stopping or
pausing the published writer succeeded; require primary-side or runtime shutdown
evidence instead. The Publishing UI exposes distinct Pause and Unpublish actions;
do not assume Pause terminates compute merely because it blocks public access.

The operator-confirmed Pause followed by another publish was tried and the
replacement still failed on the existing writer lock. Do not repeat that
sequence as a fix. Inspect the full stop/unpublish confirmation and its data
and URL consequences before asking the operator to proceed; brief-downtime
approval is not approval to delete the project or production database.

Full Unpublish followed by Publish is an owner-confirmed working handoff.
Verify that the deployment service reports no active deployment between those
steps; do not treat this as permission for future outages without approval.

**Why:** The owner confirmed the live feature worked after this handoff, unlike
the earlier Pause-based attempt.

**How to apply:** Use the full stop-before-start sequence for approved releases
while this exclusive-writer architecture remains in place.
