# Durable findings without migrating SQLite

## Approved approach and limits

The owner approved keeping SQLite and storing complete, private recovery
snapshots in the existing PostgreSQL database. SQLite remains the scanner's
working database. No tenant IDs, owner IDs, API keys, findings, scan runs, legacy
history, or other SQLite tables are reassigned or selectively imported.

The PostgreSQL database is the recovery source. Published filesystem storage,
including Reserved VM storage, is not a durable backup across replacement
deployments. The workspace `vata.db` is **not** a copy of production and must
never be used to seed production merely because it is available.

Supported operation is **one findings writer per database namespace**.
The dedicated PostgreSQL connection holds a session advisory lock for the
writer's lifetime. During a replacement, a second gateway may serve frontend
liveness while waiting for that lock, but it cannot start its scanner, restore
SQLite, provision workspaces, run schedules, or accept API traffic until it owns
the lock. Do not scale this configuration to multiple steady-state VMs or
run standalone scripts that modify the same SQLite file while it is serving.
CLI scanners and legacy `app_full.py` are not covered by the gateway's backup
contract.

## Before the first replacement: preserve the live file

**Do not replace the current deployment until a verified live snapshot exists.**
This fork cannot read the current deployment's filesystem, and publishing this
code first cannot recover data that the old deployment's replacement removes.

1. Confirm the live environment and obtain an operator-controlled way to export
   its SQLite database. If no supported access to that running filesystem is
   available, stop here and arrange that access/recovery with the deployment
   operator. Do not substitute workspace findings or claim the data is backed up.
2. Quiesce live scanning, finding submissions, and scheduled scans. Keep the old
   runtime intact until backup and recovery verification have succeeded.
3. In that live runtime use Python's SQLite backup API (not `cp` of an active
   database). The helper reads the source with `mode=ro`, includes committed WAL
   data, validates integrity, and writes a private file:

   ```sh
   python3 scripts/sqlite-snapshot.py snapshot /actual/live/vata.db /private/export/live.sqlite
   python3 scripts/sqlite-snapshot.py check /private/export/live.sqlite
   ```

   The destination must not exist. The printed value is a logical SHA-256
   fingerprint, not database contents. If this helper is not present in the old
   runtime, an operator must supply it there without replacing that runtime, or
   use equivalent `sqlite3.Connection.backup()` tooling. Transfer the verified
   export securely; never put it in Git, a published build, chat, or a public URL.
4. Review and apply `migrations/findings-backups.sql` to the intended existing
   PostgreSQL environment using the normal approved schema process. Runtime
   startup does not create tables or migrate PostgreSQL. The service role needs
   SELECT/INSERT/DELETE on this table and USAGE on its identity sequence.
   No browser or public role should have access.
5. In an operator-controlled runtime with the export and this project, configure
   the environment through the workspace/deployment secret/settings flow:

   - `DATABASE_URL`: the intended existing **production** PostgreSQL database.
   - `DB_FILE`: explicit path to the verified **live export**, never default
     workspace `vata.db`.
   - `VATA_FINDINGS_NAMESPACE`: a deliberate environment-specific name such as
     `production-findings` (3–64 lowercase letters, digits, `_` or `-`, starting
     with a letter).

   Do not print connection strings or copy credentials into shell history.
   Confirm the PostgreSQL account identity records correspond to the live SQLite
   ownership records; do not rename organizations or reassign IDs to make them
   match. Then explicitly approve the initial snapshot:

   ```sh
   npm run findings:seed -- --approve-live-snapshot
   ```

   This reads SQLite only and refuses to overwrite an existing namespace. It
   never imports `app.py` or modifies the source. Keep a separate secure copy of
   the original export until the cutover has been verified.
6. Verify restoration and the intended accounts' authenticated findings/scan
   history in an isolated rehearsal against that snapshot. Do not run two
   writers for the same namespace, or attach a development PostgreSQL account
   database to a production SQLite snapshot.

## Production configuration

Configure the new runtime with:

- `VATA_SQLITE_DURABILITY=postgres` (the default under `NODE_ENV=production`).
- The same approved production `VATA_FINDINGS_NAMESPACE` and `DATABASE_URL`.
- An explicit `DB_FILE`, such as `/tmp/vata-findings.sqlite`, whose parent
  directory already exists. This is a disposable local working copy, not the
  durable location.

Do not set the production working file to an exported workspace database.
`VATA_SQLITE_DURABILITY=local` is an explicit opt-out for development and isolated
startup tests. It prints a warning and provides **no replacement-deployment
durability**. It is not a production recovery mechanism.
Development defaults to local mode, so it neither restores nor uploads live data.
If testing durable mode in development, use a separate database and namespace.

### Leaving the temporary local-only startup

Production previously ran with `VATA_SQLITE_DURABILITY=local`, an accepted
data-loss risk: every replacement deployment started with an empty findings
database. The deployment now selects `VATA_SQLITE_DURABILITY=postgres` with
`DB_FILE=/tmp/vata-findings.sqlite` and `VATA_FINDINGS_NAMESPACE=production-findings`
(`.replit`).

No verified export from the local-only deployment was obtained, so the owner
approved seeding the namespace from
a **fresh, empty** schema instead of a live export. Findings recorded by the
local-only deployment are not carried over. Accounts live in PostgreSQL and
their scanner workspaces are re-provisioned on first use.

For this explicitly approved fresh start on Replit-managed PostgreSQL, seed once
as an operator, never during build or application startup:

1. Apply `migrations/findings-backups.sql` and
   `migrations/findings-fresh-start.sql` in **development**. Replit Publish applies
   the resulting schema diff to production. Never run production DDL in the
   build command or application startup.
2. In an operator environment connected to the **actual production database**,
   create and seed the approved empty SQLite schema:

   ```sh
   DB_FILE=/tmp/seed-findings.sqlite python3 -c "import app"
   DB_FILE=/tmp/seed-findings.sqlite VATA_FINDINGS_NAMESPACE=production-findings \
     npm run findings:seed -- --approve-live-snapshot
   rm /tmp/seed-findings.sqlite
   ```

   Workspace `DATABASE_URL` targets development, not production. Do not run the
   seed there expecting it to initialize production. Never paste connection
   strings into chat or source files. Confirm the seed succeeded against the
   intended target and a production read-only query sees its snapshot.
3. Publish only after that snapshot exists. Startup checks the exclusive writer
    lock, checksum and schema, then restores the existing snapshot before opening
    scanner/API traffic. Frontend liveness may be available earlier. It never
    seeds a missing namespace, regardless of leftover
   `VATA_FINDINGS_INITIALIZE_EMPTY` settings. Missing snapshots require an operator
   seed or recovery, not an automatic empty reset.
4. Limit the deployment to **one instance** (Autoscale max instances = 1, or a
    Reserved VM). A second instance cannot take the writer lock; it serves frontend
    liveness only during a bounded startup wait, then exits if contention persists.

Missing schema, missing snapshots, corrupt snapshots and permission failures
still fail startup. The manual seed refuses an existing namespace and does not
modify source SQLite rows or PostgreSQL ownership records. Existing receipt
tables are left intact; removing automatic initialization does not delete data.

## What happens at runtime

### Frontend liveness versus writer readiness during a publish

The platform's observed deployment checks target `/`. After validating startup
configuration and PostgreSQL account schema/connectivity, the gateway listens
and serves frontend HTML there without waiting for the previous writer. This
lets a platform promote the frontend and drain the old revision without the old
"new writer must be ready before old writer can stop" deadlock.

`/` is **liveness, not scanner readiness**. `/health` remains HTTP 503 until the
writer lock, verified snapshot restore, private scanner readiness and initial
snapshot commit all succeed. All `/api` routes return HTTP 503 with
`code: WRITER_NOT_READY`, `Retry-After: 2` and `Cache-Control: no-store` during
handoff, before authentication/account provisioning/quota reservations run.
Once ready, normal authentication and authorization apply unchanged.

Only lock contention is retried: once per second for up to 120 seconds by
default. Optional `VATA_FINDINGS_LOCK_TIMEOUT_MS` (1–300000) and
`VATA_FINDINGS_LOCK_RETRY_MS` (1–5000) tune these positive integer millisecond
bounds. A waiting candidate logs `findings_writer_waiting`, not
`findings_storage_ready`. Timeout exits nonzero without starting its scanner,
creating SQLite or acknowledging writes. Schema, permission, checksum and
snapshot failures are fatal immediately, not retried.

The private scanner has a separate 120-second cold-start readiness budget.
`VATA_SCANNER_STARTUP_TIMEOUT_MS` can set a positive millisecond value up to
300000; configuration is validated before listening. API and health readiness
remain 503 throughout scanner boot. A successful publish/root response alone
does not establish that this later phase completed.

Importing the Flask app initializes SQLite, so its process is intentionally not
started until lock acquisition and snapshot restoration finish. The scheduler
also starts only after readiness. SIGTERM cancels the retry wait and closes any
acquired session. A lock lost **after** acquisition remains fail-closed; this
startup retry path never reacquires a lock over potentially divergent local data.

Actual old-revision shutdown timing is platform-controlled. A frontend 200 is
not proof the platform has drained the old writer, or that writes have resumed.
Verify `findings_storage_ready` and `/health` HTTP 200 on the **new** revision.
If the platform keeps the old session alive beyond the configured wait, use the
operator recovery procedure below; never force startup or terminate an
unidentified connection to make a publish appear healthy.

If scanner initialization times out, a process restart can encounter a local
SQLite/schema difference from the stored snapshot. That check remains strict:
do not assume the difference is only schema, discard the local file, or weaken
the comparison. Preserve it for recovery. A corrected replacement starts from
the verified durable snapshot in its separate working filesystem; never copy a
workspace database into that replacement.

### Snapshot and write contract

- Startup acquires the writer lock and retrieves the newest snapshot for the
  configured namespace. A missing snapshot, unavailable schema/storage, checksum
  mismatch, invalid SQLite file, orphan WAL files, or conflicting local copy
  stops startup. It never silently creates an empty findings database.
- The SHA-256 of the stored bytes and SQLite integrity/schema checks are verified
  before an atomic, private, no-overwrite restore. If a local file exists, its
  full logical contents must match the snapshot. Neither side wins silently.
- After compatible SQLite schema initialization, a recovery snapshot is committed
  before the gateway becomes ready.
- All gateway calls to the scanner, including scheduled scans and workspace
  provisioning, are serialized through the storage coordinator. A changed
  database is snapshotted with SQLite's backup API and committed to PostgreSQL
  before the response returns. Failed scans and partial error outcomes are
  snapshotted too. Unchanged logical contents do not create another generation.
- The newest five complete generations are retained in the same transaction as
  the new snapshot. There is no public snapshot download/restore API.
- A failed snapshot commit returns an error instead of acknowledging success,
  marks health unavailable, and blocks further scanner operations. It does not
  delete the local data. An interrupted or timed-out request may have local
  changes even though the caller did not receive success; inspect before retrying.
- Losing the writer-lock session blocks future operations. A response already
  acknowledged in durable mode has a committed recovery snapshot. Abruptly
  interrupted, unacknowledged requests are not guaranteed recoverable.

Snapshots copy the entire database and serialize scanner requests; this strategy
is intended for the current single-VM, modest-volume service. Monitor PostgreSQL
storage and response times. Five snapshots are not a time-based archive or an
independent disaster-recovery system. Loss of the PostgreSQL database or its
account identity data requires separate database recovery.

### Capacity warnings

The service writes rate-limited JSON warnings to server logs when either:

- The combined stored payload byte lengths for the configured findings namespace
  reach `VATA_FINDINGS_SNAPSHOT_WARN_BYTES` (default: 1 GiB).
- Free space on the most constrained local filesystem used by `DB_FILE` and
  temporary SQLite snapshots reaches or falls below
  `VATA_FINDINGS_DISK_WARN_FREE_PERCENT` (default: 15%).

Set these environment variables to positive integer values appropriate for the
operator's expected data volume and local disk. The snapshot threshold is an
operator-defined warning budget, **not** a discovered PostgreSQL quota or a
prediction of managed-database capacity. PostgreSQL exposes the byte lengths of
this namespace's retained snapshots to the application, but the service does not
assume it can discover a provider's remaining capacity. The disk threshold is
checked at startup, around scanner operations, and before creating a temporary
snapshot; snapshot usage is checked at startup and after a storage operation.
Monitoring probes do not block scanning or snapshot commits. The
monitor emits another warning at most every 15 minutes per metric while the
threshold remains exceeded, and emits an informational recovery record when
measurements return below the configured limit.

Records use `event: findings_capacity_warning` with `severity: warning`, or
`event: findings_capacity_recovered` with `severity: info`. They include only
aggregate byte counts/percentages and metric labels—never snapshot contents,
findings, credentials, namespace values, or filesystem paths. These alerts use
the same approved server-logs-only destination as backup-health alerts.

The owner has separately approved an encrypted, off-project recovery/retention
policy and synthetic disaster-recovery rehearsal covering accounts and complete
PostgreSQL findings snapshots together. See
[independent recovery](independent-recovery.md) for the policy, operator tooling,
rehearsal and activation approvals. **Live independent backup delivery is not
enabled**; the policy approval does not permit exporting live records or replacing
the current database.

## Recovery and rollback

### Backup-health alerts (server logs only)

The owner approved **server logs only** for operational notifications. No email,
webhook, dashboard notification, or external service is used. The operator must
review the running service's stderr logs; this does not deliver a message to an
unattended inbox.

Search for JSON records with `event: findings_storage_unavailable` and
`severity: critical`. Reasons are `backup_failed`, `writer_lock_lost`, or
`startup_failed`. Startup failures include inability to verify the database or
durable-storage configuration. Loss of the dedicated writer session emits an
alert immediately, even while idle. Failed commits also emit an alert before
returning an error. All alerts include the recovery link
[docs/findings-storage.md#recovery-and-rollback](findings-storage.md#recovery-and-rollback).
The link is repository-relative, not a public snapshot or recovery endpoint.

Failure alerts share a **15-minute process-local rate limit** across all reasons.
Blocked requests and health polls can emit a reminder after that interval; there
is no background notification timer. `suppressed` counts failure reports/polls
omitted since the previous alert, not failed scans. The first reason is retained
until verified recovery. Restarting a process resets its limiter, so restart
loops must also be controlled by the operator.

Only fixed operational messages, reason codes, severity, suppression count, and
the runbook path are logged. Notifications never contain raw errors, database
URLs, credentials, namespace values, file paths, owners, targets, or findings.
Do not add raw exception details to these records.

Failures remain **fail-closed**: a database coming back online does not unlock
the running failed writer. Follow the preservation/recovery steps below and
start a single replacement instance. `findings_storage_ready` confirms that a
fresh process has verified its writer session and completed its initial backup
check before serving traffic. `findings_storage_recovered` is emitted when a
process that observed a failure subsequently verifies a restored coordinator;
opening a connection alone never signals recovery. A fresh process cannot know
the previous process's incident state, so its `ready` record is the restart
recovery confirmation, not evidence that an earlier unacknowledged write survived.
Normal shutdown and local-only development do not produce backup-failure alerts.

1. Stop the gateway, scheduler, scanner, and any direct SQLite writers. Preserve
   the local database **and its WAL/journal files**, the original export, and all
   PostgreSQL generations before making changes.
2. If local data differs from the newest snapshot, do not delete it or enable
   local-only mode to force startup. Make a validated SQLite backup of the local
   copy and inspect the relevant tenants' findings/history. With explicit owner
   approval, seed the chosen complete copy into a **new** recovery namespace.
   This leaves the previous namespace intact and avoids silently merging tenants
   or overwriting evidence. If newer data exists in multiple copies, reconcile
   it offline under a separately approved recovery plan.
3. If the newest PostgreSQL generation is damaged, do not silently fall back.
   An operator can select a known-good earlier generation, validate its payload,
   and copy it to a new recovery namespace after owner approval of the data-loss
   window. Use parameterized SQL; never expose the bytea payload to users.
   Preserve the damaged generation for investigation.
4. Configure the stopped deployment to use the approved recovery namespace and
   an absent working `DB_FILE`. Start one instance, then verify sign-in,
   organization ownership, findings, and completed/failed scan history. Never
   reuse a main filename with orphan WAL files.
5. A code rollback must still use durable storage and the matching account
   database. Rolling back to an old local-only build is not a data rollback and
   can lose subsequent findings on replacement.

## Verification

```sh
npm run test:findings-storage
npm run test:startup
python3 -m unittest discover -s tests -p 'test_findings_refresh.py'
python3 -m unittest discover -s tests -p 'test_dashboard_scans.py'
```

The storage test uses an isolated temporary PostgreSQL server, two fixture
owners, real Flask routes, gateway bridge calls, and built `npm start`. It checks
retrieval after a process restart and a clean replacement runtime with no local
database, full ownership/history preservation, failed/completed scans, lock
conflicts, missing/corrupt backups, divergent local data, and commit failures.
It never uses workspace or production credentials/data.
The startup suite also simulates frontend-first promotion while an old writer
holds the lock, then drains that writer and checks replacement readiness,
preserved ownership/findings, bounded contention timeout, cancellation on
shutdown, and fail-closed APIs after a lock-session loss.

This is a **replacement-publish simulation**, not proof of a real production
publish. After the approved live snapshot is seeded and the code is merged,
the operator must verify an actual controlled restart and replacement deployment,
then retrieve the same authenticated findings and scan-history records for each
test tenant. Keep the live export until that succeeds. This task does not publish
or change the currently running production database.
