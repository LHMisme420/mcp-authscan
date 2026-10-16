# VATA subscription tiers

## Rules

Free workspaces share five accepted scans per UTC calendar month across all
members. Invalid URLs are rejected before reserving quota. Accepted scans that
fail because a target is unavailable still count. Reservations are atomic in
PostgreSQL, so concurrent requests cannot exceed five. A new month gets a new
ledger entry; upgrading or downgrading does not erase usage.

Free finding records are read-only and seven-day history is enforced by the
backend for findings, statistics, compliance and scan history. Older results are
hidden, never deleted. Pro restores access to retained history.

Pro costs $99 USD/month and includes unlimited scans/history, programmatic
access, schedules and five total seats including the owner. Verified Stripe
status and period end determine access; client-supplied tier fields never do.
Organization tier, expiration and monthly usage are mirrored into SQLite.
PostgreSQL holds the authoritative usage ledger, team access, token hashes and
schedules across server restarts. Existing finding storage remains SQLite.

## API

Browser sessions use Clerk cookies. Programmatic access requires Pro and either
a real Clerk Bearer token or a scoped VATA API token. Only owners issue/revoke
API tokens; newly issued secrets are shown once, not saved in the browser.
Bearer-based Free requests cannot bypass the dashboard scan allowance.

- `POST /api/scan` — JSON `{"target_url":"https://owned-server.example/mcp"}`.
- `GET|POST /api/schedule-scan` — create with `target_url`, `frequency`
  (`once`, `hourly`, `daily`, `weekly`) and optional ISO `run_at`.
- `PATCH /api/schedule-scan/:id` — JSON `{"enabled":false}` to pause, true to resume.
- `DELETE /api/schedule-scan/:id` — stop future runs.
- `GET|POST /api/api-tokens`, `DELETE /api/api-tokens/:id` — owner controls.
- `GET /api/team`, `POST /api/team/invites`, `DELETE /api/team/invites/:id`.
- `POST /api/team/join` — authenticated user accepts a one-use invitation token.
- `DELETE /api/team/members/:userId`, `POST /api/team/leave`.

API tokens are scoped to scan, schedule and finding endpoints, not billing or
team administration. Members cannot manage billing or another member's
schedules. The owner can manage all organization schedules. Removal/leave
revokes member access, disables their schedules and restores their separate
personal workspace without deleting its data. Invitations reserve seats for
seven days; owner + members + outstanding invitations cannot exceed five.

## Worker and publishing

The next publishing configuration uses Reserved VM with the existing Node
build/start commands. It is not live until published. Every 15 seconds the
server claims a due PostgreSQL job with a five-minute lease. Missed recurring
times are skipped rather than replayed in a burst. Every run revalidates the
subscription and membership; expired subscriptions postpone jobs without
consuming Free scans. Leases allow recovery after a server restart. Pausing or
deleting a schedule stops future runs, not an already-started scan.

When publishing, review/apply the PostgreSQL schema changes represented in
`migrations/subscription-tiers.sql`. SQLite columns are added non-destructively
when Flask starts. Back up live SQLite findings before republishing: the local
workspace database is not a backup of the published server, and Reserved VM
does not make SQLite files durable across replacement deployments.

## Verification

```sh
npx tsc --noEmit
npm run build
npx tsx --test tests/billing.test.ts tests/tiers.test.ts
PYTHONPATH=. python3 -m unittest discover -s tests -p 'test_subscription_tiers.py'
npx tsx scripts/verify-account-flow.ts
```

The last script uses real development Clerk users, Stripe sandbox subscriptions,
temporary owned scan targets and disposable team/token/schedule fixtures. It
cleans up all its fixtures. It refuses production Clerk keys and charges no real
money. Signed-in rendering still requires separate browser verification.
