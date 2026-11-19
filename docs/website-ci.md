# Website checks on GitHub changes

The `web` job in `.github/workflows/ci.yml` runs on every push and pull request,
alongside the unchanged Python scanner jobs. It uses read-only repository
permissions and does not deploy or publish anything.

## What runs

`npm ci` installs the declared Node dependencies from `package-lock.json`.
An inconsistent manifest/lockfile fails installation instead of updating the
lockfile. CI uses Node 20.20.0 to match the gateway runtime and Python 3.11 for
the private scanner/startup fixtures. The scanner's runtime dependencies come
from `requirements-runtime.txt`.

`npm run test:ci:web` runs, in order:

1. `npm run typecheck`: the existing TypeScript configuration, without emitting
   files.
2. `npm run test:billing`: server billing-disabled contracts and static React UI
   regressions, including stale `live` and `test` flags.
3. `npm run test:startup`: the React production build and bundled Node gateway,
   followed by startup unit checks and the built `npm start` integration suite.
   These check frontend liveness, health/readiness, unauthenticated access
   rejection, disabled payment routes, private scanner startup/failure,
   findings writer handoff and shutdown.

`tests/live-billing.test.ts` is no longer present: payments and the live
integration were removed. CI deliberately runs the current removal regressions
instead of recreating a billing implementation.

## Isolation and cleanup

The workflow contains only public, nonfunctional fixture credentials. It does
not reference repository/environment secrets, a customer database, real Clerk
accounts, Stripe credentials or payment connectors.

PostgreSQL 16 server binaries are installed on the runner. Rather than use a
shared database URL, `tests/startup.test.ts` creates its own disposable
PostgreSQL service: a new cluster in a unique temporary directory, listening
only on `127.0.0.1` on a dynamically assigned port. Its fixture administrator
creates synthetic account tables and roles there. Schema alterations, deletes
and session termination target only this test-owned cluster. The test ignores
any inherited `DATABASE_URL`.

Child applications receive an allowlisted environment with fake Clerk/JWT
values, test-owned SQLite files and the fixture PostgreSQL URL. Test teardown
stops the child process groups, closes its database client, stops its own
PostgreSQL cluster and removes only its temporary directory. The GitHub runner
is also disposable; there are no database cleanup commands against a shared
service.

To run the same checks locally, provide the declared Node/Python dependencies
and `initdb`/`pg_ctl` on `PATH`, then run `npm run test:ci:web` as a non-root user.
Missing prerequisites fail the tests; they are not silently skipped.

## What a green check does not prove

These are offline provider checks, not a signed-in browser test. Static React
rendering does not establish real Clerk login, organization authorization,
cross-organization access protection or the complete dashboard experience.
Those require separately authorized acceptance checks.

No Stripe requests, checkout sessions, real charges or real webhook deliveries
are made. If payments are explicitly restored in future, manual checks must
separately establish live-account authorization, callback URL registration,
Stripe-origin signature validation/delivery and subscription reconciliation.
A fake credential or locally constructed event cannot establish any of those,
and a green build is not permission to activate payments.

CI also does not prove published routing, production database readiness,
production credentials or that a new revision is actually live. Those remain
separate release checks; this workflow never invokes publishing actions.
