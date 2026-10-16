# Running on Replit

This imported project contains the `mcp-authscan` Python command-line scanner and a hybrid Node/Flask VATA dashboard. Scanner findings remain in SQLite; accounts and scheduling use PostgreSQL.

Payments are disabled **by default in Preview and production** for the current
payments-free release. The project's Stripe connector must also be disconnected
in Replit's Integrations UI to remove Publishing's live-account authorization
requirement; disabling application billing alone does not remove that check.
Billing code is retained for future use. Restoring Preview test checkout later
requires a sandbox connector and explicit development `VATA_BILLING_MODE=test`.
Live billing preparation is implemented but not activated: see
[Live billing launch](docs/live-billing-launch.md). Production requires explicit
`VATA_BILLING_MODE=live` before it accepts live-mode billing, and new checkout
stays closed until a signed live catalog webhook arrives. The separate first-
launch switch `VATA_PREPARE_LIVE_BILLING=1` runs scoped setup after HTTP readiness
using the production connector; it never creates customers or charges.
Startup requires no payment credentials or Stripe schema while billing is
disabled. Scans, full history, API tokens, schedules and teams then remain
unrestricted by subscriptions; sign-in, organization ownership, owner-only
controls and five-seat capacity remain.
Historical account records are retained. Existing external Stripe subscriptions,
if any, are not canceled or changed by this feature.

The following billing tools are retained for future use, not current startup.
After restoring the sandbox connector, prepare its catalog with `npm run checkout:prepare`. This validates
test-only credentials, creates a $99/month test price through Stripe, and syncs it
into the SDK-managed Stripe schema. It never runs as a startup migration.
`npm run checkout:verify` creates, checks and expires a synthetic test session.
When Preview test billing is explicitly enabled, owners see **Stripe sandbox · test only** in their dashboard.
Payment confirmation and subscription status are retrieved directly from Stripe,
never trusted from a return URL. This standalone checkout does not grant paid
status or entitlements.

The fuller **Preview-only** billing experiment is also retained: unlimited
manual scans and full history remain free, while test Pro costs $99 USD/month
for API access, scheduling and five seats. See [Stripe billing](docs/stripe-billing.md).
Its owner-only billing panel, checkout, portal and explicit refresh support both
test and explicitly enabled live billing. Optional billing sync starts after
gateway readiness and does not register, enable or replace callbacks; only the
separately approved setup job can add its own callback. Without explicit live
opt-in, production remains subscription-free.

`npm run checkout:rehearse` uses synthetic Stripe test-clock customers to verify
successful payment, initial decline, failed renewal, cancellation, notification
signatures, concurrent retries and stale-event recovery. It removes its own Stripe
fixtures and notification receipts afterward; it never changes existing customers
or workspace access. Test card entry in a browser is a separate check.

The Preview-only notification route is `/api/test-checkout/webhook`, registered
before JSON parsing and interactive authentication. It verifies signatures with
the SDK-managed secret for this exact endpoint and connected test account.
Receipts use PostgreSQL event/entity locks and are committed only after a
successful sync. Subscription reconciliation refetches current Stripe state even
for terminal notifications, avoiding stale or same-second cancellation snapshots.
No notification mutates account ownership, tiers or feature access.

`npm run checkout:connect-test-webhook` registers only this Preview's test callback
and preserves other endpoints. It uses Stripe creation plus the SDK's scoped
upsert API: the SDK's global find-or-create helper can delete other managed URLs.
`npm run checkout:connect-test-webhook -- --disable` disables only this callback.
`npm run checkout:verify-delivery` waits for Stripe-origin delivery receipts before
making any manual replay. `npx tsx scripts/verify-test-subscriptions.ts
--external-replay-only` tests signed HTTP requests without claiming automatic
Stripe delivery.

The Preview handler passed signed HTTP lifecycle replays. Automatic Stripe-origin
callbacks did not arrive within the test window, so this new callback was
disabled while investigating; previous callbacks were not modified. Do not enable
live billing until actual provider delivery is confirmed. Inspect the exact
Preview endpoint's Stripe delivery history, not only its enabled status.

Check external reachability rather than assuming Preview is private or public.
Do not change privacy without approval. Signed replays are not proof of external
Stripe delivery. Production checkout and notification routes remain disabled
unless live mode is explicitly enabled. Gateway readiness never waits on Stripe.

## Web dashboard

Use Replit's Run button / **Start application** workflow, which runs:

```sh
npm run dev
```

The Node gateway serves the React dashboard and Clerk-authenticated API on `0.0.0.0:5000`. It starts Gunicorn with `app:app` on private loopback port 5001. `/health` checks PostgreSQL schema and scanner readiness without requiring sign-in. `app_full.py` is a separate legacy API entry point.

Production uses `npm run build` followed by `npm start`. Run `npm run test:startup` to verify that exact startup path with isolated database fixtures. See [production startup verification](docs/production-startup.md) for prerequisites, coverage and limits. Managed PostgreSQL provisioning/schema changes belong to Publish, never application startup.

Configuration:
- `SESSION_SECRET`: existing Replit secret used for JWT signing, unless `JWT_SECRET` is supplied. Startup fails if neither exists.
- `VATA_PORT`: public gateway port, defaults to `5000`. The Node gateway ignores `PORT` to avoid conflicting imported secrets.
- `VATA_SCANNER_PORT`: private scanner port, defaults to `5001`; always bound to loopback and must differ from the public port.
- `PORT`: only a fallback when running `app.py` directly; the Node gateway sets the child scanner's port explicitly.
- `DATABASE_URL`: required PostgreSQL connection; missing configuration/schema fails startup with a publish-time provisioning/schema message.
- `DB_FILE`: SQLite filename, defaults to the imported `vata.db`. Do not use Replit's PostgreSQL `DATABASE_URL` as a SQLite filename.

The dashboard can run an MCP server scan from the **Scan an MCP server** form. The authenticated `POST /api/scans/mcp` endpoint accepts a `target_url` and optional `timeout`; `GET /api/scans/mcp` returns the organization's recent scan history. Scans use the `mcp_authscan` package, store failed checks as findings for the token's organization, and record completed or failed runs in SQLite. The findings, scan history, critical alerts, and compliance score refresh in the dashboard.

The scan form also accepts public HTTPS GitHub repository URLs in
`https://github.com/owner/repository` format. These use the bundled static
source scanner with JSON output, not live HTTP checks. Repository code is never
executed or installed. Clone/scanner failures return errors and are saved as
failed runs; findings retain their actual severity. `/api/scan` is an alias
for the same authenticated scan flow. Authenticated `/api/test` reports scanner
and database readiness without exposing local paths or directory listings.

## Command-line scanner

From the Shell:

```sh
python3 -m mcp_authscan.cli --help
python3 -m mcp_authscan.cli scan https://YOUR-AUTHORIZED-MCP-SERVER --format json
```

Only scan systems you own or have permission to test. A scan exits with status 1 when critical findings are detected.

## Authentication and storage notes

The hybrid gateway uses Clerk sign-in and signed account-bridge tokens for scanner API access. Do not expose the private scanner port publicly or use legacy organization-name registration as secure authentication.

The production UI is bundled by Vite and served by Node; Flask runs under Gunicorn.
Scanner findings remain in SQLite with owner-approved full recovery snapshots in
the existing PostgreSQL database. Production defaults to durable mode and requires
an explicit `DB_FILE`, `VATA_FINDINGS_NAMESPACE`, the reviewed
`migrations/findings-backups.sql` schema, and a seeded **live** snapshot before
replacement. Never seed production from the workspace SQLite file. See
[findings storage and safe cutover](docs/findings-storage.md) before changing a
deployment. Development defaults to local-only storage with a warning.

Independent PostgreSQL recovery/retention policy and a synthetic full-database
rehearsal are documented in [independent recovery](docs/independent-recovery.md).
Run `npm run test:independent-recovery` for the isolated disaster simulation.
Live off-project exports, destination/key custody, and any production recovery
still require separate owner approval; no external backup schedule is enabled.
