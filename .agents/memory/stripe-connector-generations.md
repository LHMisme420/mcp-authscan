---
name: Stripe billing scope
description: Current owner-approved Stripe removal and superseded billing approvals.
---

## Current owner instruction

The owner asked: “please update this as i am tryign to publish deactivate and remove stripe”.
Earlier approvals for billing preparation below are superseded. Do not restore
Stripe automatically or use historical billing tasks as authorization to reconnect it.

**Why:** Repeated live-authorization requirements blocked the owner's payments-free release.

**How to apply:** Keep the project payment-free unless the owner explicitly asks
to restore payments. Removing app code is not the same as disconnecting the native
project connector; do not claim that Publishing's authorization blocker is cleared
until that connection is actually detached. Preserve historical ownership records
and do not cancel external subscriptions without separate authorization.

## Superseded historical approvals

The owner previously said: “remove the billing and stripe from it period. its creating issues”.
They have now explicitly asked: “lets work on stripe”.
They subsequently confirmed **$99 USD per month**, with **advanced features
only** paid: API access, scheduling, and team features. Basic scans stay free.
The owner subsequently approved **"Prepare live $99/month Pro billing"** after
being told this would charge for API access, scheduling, and team features while
basic scans and full history remain free. This authorizes live billing preparation,
not immediate activation, publication, or an agent-made real purchase. Live
authorization, verified Stripe-origin delivery, and publish approval remain
separate launch steps. If Preview payments are enabled, they must remain test-only.

The owner subsequently chose **"Prepare the website to publish without Stripe
payments"** after live connection installation failed. For this release, disable
payments in Preview and production and detach the project's Stripe connection,
while retaining the billing code and external Stripe records.

**Why:** The owner approved a payments-free release to stop the live-installation
failure from blocking publication.

**How to apply:** Do not reactivate payments automatically or cancel external
subscriptions. Restoring test or live billing requires separate approval and
appropriate connector authorization.

**Why:** Repeated live-authorization publishing failures led the owner to
remove billing; they subsequently explicitly requested renewed Stripe work.

**How to apply:** Keep production subscription-free until live activation is
approved separately. Keep manual scans and full history free in both modes, with
no scan quotas or history restrictions. Use the confirmed monthly USD price.
Do not weaken sign-in, tenant ownership, or owner-only team/token
management. Preserve historical database records. Do not cancel or delete
anything in the owner's external Stripe account without separate authorization.

## Publishing authorization is separate from app readiness

Do not call a Stripe-connected release ready to publish solely because its
build and health checks pass. Verify Publishing's live-account authorization
separately, even when production billing is disabled in the application.

**Why:** Publishing blocked a release with “Connect a live Stripe account before
publishing” despite a healthy workspace test connection and disabled production
billing. This pre-build check did not create a failed build-history entry.

**How to apply:** Keep a working test connection intact unless the owner explicitly
approves detaching it, as they did for the payments-free release. A test-mode API response
does not establish whether production authorization exists. Inspect the actual
Publishing authorization state before asking the owner to repeat installation or
changing application code.
