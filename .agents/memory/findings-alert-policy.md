---
name: Findings alert policy
description: Owner-approved notification destination for findings backup health.
---

Use server logs only for findings backup failure and recovery notifications.
Do not add email, webhooks, or another external notification destination without
owner approval.

**Why:** The owner explicitly chose “Server logs only” when asked where backup
failure alerts should be sent.

**How to apply:** Keep notification payloads free of credentials and findings,
and direct operators to the findings storage recovery guide.
