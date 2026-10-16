---
name: Stripe proxy compatibility
description: Connector generation and multi-account sync hazards when restoring Stripe.
---

Use the current connection's supplied authentication instructions rather than
assuming the legacy secret-export endpoint will provide an API key.

**Why:** This project's renewed Stripe connection successfully authenticated
through the connector proxy while the old secret-key template returned no
usable credentials. The absence of exportable keys was not a failed connection.

**How to apply:** Keep authentication inside the supported SDK proxy transport.
Do not request extra Stripe secrets or repeatedly reconnect a working proxy
connection to satisfy the legacy template.

Full synchronization must enumerate customers only from the currently connected
Stripe account, not all historical customers in the local mirror.

**Why:** A backfill failed on a nonexistent customer because the sync library
enumerated mirror customers without account scoping after reconnection. Historical
records belong to previous connector accounts and must not be deleted or claimed.

**How to apply:** Preserve account-scoped synchronization, keep the current
compatibility guard when upgrading the library, and verify the upstream behavior
before removing it. Never repair this by deleting historical customer rows.
