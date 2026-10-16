---
name: Stripe webhook reconciliation
description: Terminal webhook snapshots can leave the Stripe SDK mirror stale after cancellation.
---

After accepting a subscription notification, reconcile current Stripe state via
the official sync SDK before committing the app's delivery receipt. Serialize
related notifications by subscription, not only by event ID.

**Why:** A real test-clock rehearsal showed a canceled Stripe subscription still
mirrored as past_due. The sync SDK can bypass API revalidation for terminal event
snapshots, whose second-resolution timestamps lose against recent API syncs.
Enabling its general revalidation option alone did not prevent this.

**How to apply:** Use authoritative SDK refetches, not hand-written updates to its
schema or a duplicate app subscription-status table. Keep event receipt commits
after successful reconciliation, verify signatures even on replays, and retain
the stale-event/cancellation rehearsal. Signed fixtures or HTTP replays verify
processing, not actual Stripe-origin delivery. Check the precise callback from
outside before inferring Preview privacy; privacy changes need separate approval.

Add sandbox callbacks without replacing existing managed URLs.

**Why:** The SDK's global find-or-create routine can delete other managed
callbacks when their URL differs, including callbacks outside the current test.

**How to apply:** Create only the scoped test endpoint through Stripe and persist
it through the SDK's public managed-webhook upsert API. Preserve previous
endpoints. If a rehearsal fails, disable only the callback created for it; do not
rotate someone else's signing secret or remove their callback to make tests pass.
