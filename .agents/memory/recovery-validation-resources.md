---
name: Recovery validation resources
description: Resource limits and duplicate synthetic recovery runs during completion checks.
---

Run the scaled independent-recovery rehearsal only once at a time. Avoid keeping all multi-gigabyte fixture copies on the separately quota-limited system temporary disk, but keep synchronous database I/O off slow workspace storage.

**Why:** Filesystem free-space reports do not account for every temporary-disk quota. Conversely, workspace storage can have much slower synchronous WAL writes: loading the retained generations there took over ten minutes. Recovery rehearsals need both storage headroom and an appropriate filesystem for database I/O.

**How to apply:** Separate large archive/snapshot copies from the active temporary PostgreSQL cluster, keep fixtures excluded from Git and deployments, and avoid concurrent scaled rehearsals. Preserve the workload and assertions. Resource troubleshooting must never delete application data or bypass a configured recovery check.
