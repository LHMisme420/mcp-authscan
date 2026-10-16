---
name: Published startup evidence
description: Why publishing port fixes need production startup evidence rather than preview checks alone.
---

Treat the published process's bind address and port as the authoritative evidence of startup behavior. A saved run-command override and a working preview do not prove that the published process used that override.

**Why:** A failed publish started Flask on port 3000 while the health check expected 5000, despite the workspace showing a startup command intended to select 5000. An imported PORT secret also existed. The exact reason the command override did not take effect was not established.

**How to apply:** Check logs for the specific failed publish before declaring a port fix successful. Test conflicting port settings locally, then distinguish a verified local correction from a confirmed successful publish.

A successful build-history entry does not establish current runtime health.
Check workflow/browser logs and production runtime logs independently, and label
which environment each error belongs to.

**Why:** Repeated publishing reports showed unchanged successful build history,
while separate preview logs exposed a concurrent first-visit workspace creation
failure. Treating the history alone as proof that there were no errors missed it.

**How to apply:** If no new failed build is recorded, inspect runtime evidence
before asking for a screenshot again. Do not present a preview fix as a confirmed
fix for a production publishing failure.

Keep managed PostgreSQL schema repair out of runtime initialization, including
third-party billing initialization.

**Why:** Production provisioning and schema application belong to Publish.
An application that silently migrates during startup can race with that flow;
a successful local build cannot establish production database readiness.

**How to apply:** Verify startup against disposable databases with synthetic
credentials and a read-only application role. Fail clearly on missing schema
instead of attempting repairs, and keep live-provider verification separate
from isolated startup evidence.
