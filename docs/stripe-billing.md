# Stripe test billing

> Historical reference only: Stripe code, SDKs, payment UI and all setup scripts
> described below have been removed. Environment flags cannot restore payments.

Payments are currently disabled by default in Preview and production. This
implementation is retained for future use. Reconnect the sandbox connector and
explicitly set development `VATA_BILLING_MODE=test` before using these tools.

## Approved plans

These plan and entitlement experiments are **Preview-only**. Production keeps
subscription-free API access, scheduling and teams; all production billing,
checkout and webhook endpoints return 410, and Stripe initialization is skipped.
No production paid entitlement is granted or required by this work.

- **Free:** unlimited manual MCP scans, complete findings and scan history.
- **Pro:** **$99 USD per month** for programmatic API access (including Clerk
  bearer access), automated scheduling, and up to five seats including the owner.
- Workspace owners alone create checkout sessions, manage subscriptions, invite
  users, and create/revoke API tokens. Paid team members inherit the owner's
  entitlement, not a personal subscription.
- No scan quota or seven-day history limit is reintroduced.

Only **test mode** is implemented. The application explicitly refuses a live
Stripe connection. Connecting Stripe does not publish this branch, activate real
charges, cancel historical subscriptions, or resume findings backups.

## Setup and startup

Use the existing Stripe connection and PostgreSQL account database. No manual
Stripe keys are required. The new connector authenticates through
`@replit/connectors-sdk`; credentials stay with the connector. The Stripe SDK
uses its authenticated fetch transport. `stripe-replit-sync` owns the `stripe`
schema, managed webhook signature handling, backfill, and synchronized objects.
Application queries are scoped to the verified connected Stripe account.

Run once (safe to rerun in the connected sandbox):

```sh
npm run billing:setup
```

This creates the test product and recurring price through Stripe, with a stable
lookup key and idempotency keys. It also configures the test customer portal for
invoices, payment-method updates, and end-of-period cancellation. It does not
create live prices or subscriptions. Existing catalog or account records are
not deleted.

Sandbox preparation also applies `migrations/test-webhook-receipts.sql`.
Both `billing:setup` and `checkout:prepare` prepare this same test receipt table.
Preview's signed billing callbacks use account/endpoint-scoped test receipts;
they do not require the production-only live-billing migration. No application
receipt tables are created automatically at startup.

The Preview gateway initializes billing **after** listening. It runs the library's
Stripe-schema migrations and backfills Stripe. It does not register, enable,
delete or replace webhooks. Callback setup is a separate explicit action,
and any intentionally disabled Preview callback remains disabled.
Application account-schema migrations remain an explicit operator action, not
startup behavior. `/health` checks accounts and scanner readiness, not Stripe.
A failed billing initialization logs a fixed stage label and retries in one
minute. Paid features are unavailable until verification is ready; owners can
still sign in and use Free scans and history.

The existing account schema must retain `stripe_customer_id`. In development,
the canonical app origin uses the preview domain. Any separately approved future
production setup must explicitly configure `PUBLIC_APP_URL` to the verified
published origin; it controls checkout/portal return URLs and the managed
webhook, never a browser-supplied redirect.

## Payment and ownership checks

`POST /api/checkout` uses only the server-verified $99 USD monthly Stripe price.
It ignores client-supplied price, customer, account and redirect values.
Account-row locking, Stripe idempotency keys, open-checkout reuse, and an
authoritative subscription lookup prevent duplicate checkout/subscription
creation on retries. Existing customers must carry matching original account
and Clerk ownership metadata; old name-only organizations are not auto-claimed.
An unresolved historical customer link requires separate ownership verification.

`POST /api/billing/refresh` retrieves the owner's actual subscriptions and uses
the library to synchronize them. A success redirect alone never grants Pro.
Only a matching active, unexpired test subscription grants access. Unpaid,
incomplete, past-due, paused or canceled subscriptions do not. End-of-period
cancellation retains Pro while the active paid period remains valid.

The raw `POST /api/stripe/webhook` route is registered before JSON parsing and
does not require a user session. It verifies Stripe's signature using the managed
secret for this exact URL and connected account before delegating to the library.
Event/entity locks serialize retries and related notifications; receipts commit
only after current subscription state is re-fetched. It refuses processing when
that exact callback has not been configured. The retained standalone callback
at `/api/test-checkout/webhook` follows the same reconciliation safeguards.

Incoming sandbox delivery testing confirmed signed HTTP replays, not automatic
Stripe-origin delivery. Its callback was disabled afterward and is not enabled
by this merge. Do not infer webhook delivery or production readiness from a
successful manual refresh or replay.

`GET /api/billing/status` and the account summary expose current verified
capabilities. `POST /api/billing/portal` returns an owner-only managed portal.
Owners retain token revocation, schedule pause/delete, and team cleanup after
downgrade; new tokens, new/resumed schedules, and invitations require Pro.
The schedule worker also checks Pro before running a due scan.

## Verification and limits

```sh
npx tsc --noEmit
npm run test:billing
npm run test:startup
npx tsx --test tests/workspace-access.test.ts tests/tiers.test.ts
```

The billing HTTP fixtures have synthetic session context only inside their
private test app. No fixture bypass is added to the real Clerk-protected app.
Tests cover owner restrictions, account/customer mismatches, expired/canceled
status, fixed checkout terms, duplicate checkout reuse, subscription refresh,
and portal ownership.

For an explicit connected-sandbox rehearsal:

```sh
npm run billing:verify-sandbox
```

This requires development mode and verifies test mode before creating anything.
It creates a synthetic account/customer, uses Stripe's test payment token,
creates/expires a hosted checkout, confirms an active subscription through
Stripe, synchronizes and verifies Pro, tests ownership mismatch, cancels the
test subscription, and checks Free access. It removes the synthetic account
and customer on exit. Cleanup failures are reported, not silently ignored.
It does not use a real card, a real Clerk user, a live charge, or live findings.

The connected sandbox API lifecycle check passed. This is **not** a completed
browser checkout, proof of public webhook delivery, signed-in UI verification,
or a live billing launch. Those need separate acceptance testing. The offline
production recovery fixtures have no Stripe connection and must retain
subscription-free owner, API and member access.

The incoming standalone checkout experiment is also retained under
`/api/test-checkout` (and `/api/checkout` with a request ID), along with its
`checkout:prepare`, `checkout:verify` and `test:checkout` scripts and owner-only
Preview panel. It confirms test sessions without changing access. Both sandbox
paths use the current connector proxy and refuse production or live credentials.
