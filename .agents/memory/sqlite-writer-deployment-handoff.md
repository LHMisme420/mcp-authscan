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
