# Production startup verification

Run `npm run test:startup` before publishing changes to startup. This builds the
real client and server, then launches the exact `npm start` script. It requires
Node/npm, PostgreSQL 16 command-line tools (`initdb`, `pg_ctl`), `ps`, and the
Python dependencies in `requirements.txt` (including Gunicorn). Run as a
non-root user, as required by PostgreSQL.

## Isolation and coverage

The test creates a temporary PostgreSQL cluster on loopback and temporary
scanner SQLite files. Its subprocess environment contains only local tool paths
and synthetic credentials; it does not inherit workspace database, Clerk,
Stripe, or signing credentials. All fixture files and processes are cleaned up.
The database role used by the application has only SELECT permissions and
defaults to read-only transactions. Fixture setup is the only schema writer.

Checks include:

- Built `npm start`, production HTML at `/`, and unauthenticated `/health`.
- PostgreSQL schema and private Flask readiness before opening the public port.
- Missing or malformed `DATABASE_URL`, unavailable PostgreSQL, missing tables,
  columns and Stripe schema, and insufficient SELECT permissions.
- Missing signing configuration, invalid ports, missing Gunicorn, failed Python
  boot, and a scanner that never reports ready.
- API authentication remains required on both the public and private servers.
- Live database readiness loss returns 503 without exposing connection details.
- Scanner exit stops the gateway with a nonzero exit; graceful shutdown stops
  the scanner as well.

The public gateway uses `VATA_PORT` (default 5000), intentionally ignoring an
unrelated `PORT` secret. Gunicorn binds only to `127.0.0.1` using
`VATA_SCANNER_PORT` (default 5001). The two ports must differ. Test-specific ports
allow this suite to run alongside the preview.

## Publishing remains a separate prerequisite

A successful build or isolated startup test **does not prove that production
PostgreSQL exists**, that its schema is current, or that live Clerk/Stripe
credentials work. No production database was provisioned by this check.

For Replit-managed PostgreSQL, provision/review the development-to-production
schema changes in the Publish flow. The application performs only read-only
application-schema checks before serving; it does not apply account migrations.
Optional test billing initializes after listening and uses the Stripe library's
own migrations, separately from application readiness.
The standalone fixture SQL is not a production migration script.

Missing database configuration/schema causes a clear startup failure instead of
serving a misleading healthy response. `/health` reports database and scanner
readiness with HTTP 200 or 503; it does not certify billing-provider readiness.
Stripe initialization still runs after the gateway starts and logs a separate
failure if billing cannot initialize. Existing paid-account endpoints remain
unavailable until billing verification is ready.

After an authorized publish, verify the actual production startup logs and
public root/health responses. Local fixture success is not evidence of a
successful production publish.
