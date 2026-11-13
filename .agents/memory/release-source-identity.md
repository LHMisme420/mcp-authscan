---
name: Release source identity
description: Why publishing must verify actual staged input and compiled output rather than trust a recorded Git revision.
---

Treat a release's actual staged source fingerprint and verified artifact content
as its source identity, rather than relying on its recorded Git revision alone.
Refresh the saved next-publish fingerprint after approved source changes; do not
remove the check just to let a mismatched snapshot publish.

**Why:** A successful deployment freshly compiled the older commercial website
while naming a Git commit that locally contained the newer assessment pages.
Cache-busting did not change the response, and the old HTML, client and server
sizes appeared in the build log itself. The platform's underlying staging
mechanism was not established; do not invent a definitive explanation.

**How to apply:** Follow the maintained web-release verification runbook. Verify
both actual staged bytes and emitted module/artifact evidence. Keep negative
checks fail-closed, before storage/application startup. Distinguish a verified
workspace deployment build from a confirmed live release; an owner-approved
publish and live inspection are still required for the latter.
