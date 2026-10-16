# Independent PostgreSQL disaster recovery

## Approval and current status

The owner approved **the policy below and a synthetic recovery rehearsal**.
This is additional to, not a replacement for, SQLite with PostgreSQL snapshots.
That policy approval alone did not authorize exporting live sensitive records,
choosing a provider/account, or storing an encryption key. Separate activation
approval is required and must be recorded with the owner/operator before the
first live run. No approval authorizes replacing the existing database or
publishing.

**No independent live backup is enabled yet.** The repository now includes an
opt-in Google Cloud Storage delivery job and deployment files, but an operator
must deploy and schedule them in the separately owned Google Cloud project,
provision the secrets, confirm source access, and verify the first copy. No
production data has been exported by this repository change. Until the external
job is running and verified, losing PostgreSQL can still lose both account
ownership and findings. A local encrypted archive, five generations in
PostgreSQL, and another database in the same project are not independent backups.

## Approved recovery and retention policy

| Item | Policy |
| --- | --- |
| Recovery unit | One complete, consistent PostgreSQL database dump, including account ownership and `public.vata_findings_backups` together |
| Independent location | Owner-controlled storage **outside this Replit project, under a separate account**, with credentials and deletion access independent of the app's database/runtime |
| Confidentiality/integrity | Authenticated encryption before transfer; TLS for transport; no public links or public read access |
| Frequency | One successful verified copy daily |
| Daily retention | 30 days |
| Monthly retention | One verified daily recovery point per calendar month, retained for 12 months |
| Recovery-point target | At most 24 hours of lost data, conditional on daily verified copies succeeding |
| Recovery-time target | Four hours, a target to prove operationally, not a guarantee from a small fixture |
| Recovery acceptance | Isolated restore, full ownership and history verification, authenticated cross-tenant denial, explicit owner acceptance of the loss window before any live cutover |

Use UTC dates for daily/monthly labels. Keep monthly recovery points separately
from the daily expiration rule so daily cleanup cannot delete monthly copies.
Apply expiration only after verifying a newer independent copy. Never delete
the last verified recovery point automatically during a backup incident; escalate
to the owner if this conflicts with the approved retention/deletion obligations.
Storage lifecycle settings and access controls must be reviewed at activation.
Rehearse quarterly and after schema, auth-provider, or archive-format changes.
Log backup/rehearsal success or failure and age without sensitive details.
Notifications remain **server logs only**, per the existing alert policy.

### What is included

The tool uses full `pg_dump --format=custom --no-owner --no-acl`, not a selective
findings export. A single PostgreSQL MVCC snapshot contains:

- All accounts with original integer IDs and Clerk subject IDs, memberships,
  invitations, API-token hashes/revocations, quotas, and scan schedules.
- Every retained namespace and generation in `public.vata_findings_backups`,
  checksums, payloads, timestamps, and identity-sequence state.
- Other database schemas and dependencies, including the Stripe mirror.

Each SQLite payload is complete: organization ownership, API keys, findings,
completed/failed scans, and any legacy tables. These archives are **sensitive**.
Encrypt them even though API tokens in PostgreSQL are hashed. Never attach
archives, plaintext dumps, keys, or restored records to chat, Git, the Library,
published builds, or public URLs.

PostgreSQL does **not** contain Clerk's sign-in credentials/user directory,
Stripe's authoritative payments, deployment secrets, encryption keys, or
PostgreSQL cluster-global roles. Preserve access to the **same production Clerk
tenant** independently; identical display names or emails in a new tenant are
not identical owners. Never remap Clerk IDs or organization IDs to force a
restore to work. If that Clerk tenant is lost too, stop for a separately approved
identity-recovery process. Reconcile billing with Stripe rather than trusting an
old mirror as authority.

Roles/ACLs are deliberately not restored. The operator must provision a new
restricted service role and explicitly revoke public access to
`public.vata_findings_backups` before any future live service is connected.
The isolation rehearsal uses a disposable fixture role; its permissions are
not a production security configuration.

## Activation: before any live export

The owner/operator must approve and record, outside this repository:

1. The exact source environment and database, off-project storage provider,
   separate owning account, region, access/deletion permissions, retention
   configuration and any storage costs.
2. Custody and secure independent recovery of a fresh random **32-byte binary
   encryption key**, stored separately from the archives, not in this project or
   alongside backups. Losing that key makes the archives unrecoverable.
3. Authorization for the first sensitive export and daily recurring exports,
   the operator/scheduler responsible, and the means to verify copies.
4. A quiescence window: stop all scanner, gateway, scheduler, account/team,
   webhook and direct database writers. Confirm the latest SQLite changes have
   committed to PostgreSQL. Preserve dirty local SQLite/WAL files separately if
   they differ; do not silently claim an older committed payload includes them.

A full PostgreSQL dump is internally consistent while online, but pausing
application writers is important for checking SQLite ownership against account
changes and for a verified cutover. The original first-live-SQLite preservation
requirements in [findings-storage.md](findings-storage.md) still apply.

The backup operator needs a compatible PostgreSQL `pg_dump` (same major version
as the source, or a supported newer version), Node, project dependencies, and
permission to read **all** application schemas/tables/sequences. The archive
tool must be run only on a trusted operator host; no public recovery API exists.
The source preflight requires the account/ownership tables and at least one
account and findings-backup record; an empty or incomplete database fails rather
than producing a misleading empty recovery archive.
Use the approved secure environment/settings flow for connection credentials,
not command-line URL arguments or shell history:

- `VATA_RECOVERY_SOURCE_URL`: explicitly selected PostgreSQL source. It never
  defaults to the app's `DATABASE_URL`. TLS URL options supported by the tool:
  `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `channel_binding`.
- `VATA_RECOVERY_KEY_FILE`: absolute path to the securely provisioned binary key
  on the operator host; a regular file readable only by its owner (mode `0600`).
- For the Google Cloud Run Job only, `VATA_RECOVERY_KEY_B64` is the base64 form of
  the same 32-byte key, stored as a pinned Secret Manager version. The job writes
  a private temporary `0600` file for `recovery-archive.ts` and removes it on exit.
- Choose a new archive filename in a private directory. Its parent must exist.

After separate live-export approval only:

```sh
npm run recovery:archive -- export --approve-sensitive-export /private/recovery/daily-YYYY-MM-DD.vata-dr
```

The approval flag is an operator acknowledgement, **not a substitute for owner
consent**. Export streams directly from `pg_dump` through AES-256-GCM encryption
with a fresh random nonce; no plaintext dump is created. The version header is
authenticated too. A failed export leaves no final archive. Existing files are
never overwritten. Errors are redacted; credentials are sent via the child
environment, not arguments. Do not enable command tracing or environment dumps.

Transfer the encrypted file to the approved independent location over TLS,
download it into a private operator location, and compare its SHA-256 with the
original. Rehearse decryption/restoration from the downloaded copy, not just the
local source. Record UTC backup time, success, checksums, and verification status
privately, without rows or credentials. Only then mark the recovery point
successful and allow approved retention expiry. Independently recover the key
as part of the rehearsal. Do not store a key with the archive.

## Google Cloud scheduled delivery

The operator job uses the existing `scripts/recovery-archive.ts` encryption and
restore format. `scripts/recovery-gcs.ts` verifies that the configured bucket is
private, US multi-region, and Standard before it exports. It then uploads a
unique UTC-dated encrypted archive, downloads it into a private temporary
directory, and compares SHA-256 checksums before marking it verified. On the
first successful run of each UTC month, it stores a separate monthly copy.
Retention runs only after the new daily and monthly recovery points are verified:
daily objects older than 30 UTC days and monthly objects older than 12 calendar
months may be removed. No Cloud Storage lifecycle delete rule should be added;
the job must retain the last verified recovery point during failures.

The GCP job is not deployed or scheduled by the web app. Build it from the
repository root with `Dockerfile.recovery` and `cloudbuild.recovery.yaml`. Before
building, determine the source PostgreSQL major version. Set the build's
`PG_MAJOR` to that version or a supported newer version; the job checks
`pg_dump` compatibility against the explicitly selected source and fails before
export if the client is too old. `.gcloudignore` excludes local databases,
archives, keys, environment files, build output, and dependencies from the
Cloud Build upload.

Configure a Cloud Run Job in the owner-controlled project with:

- One dedicated runtime service account. Grant `roles/storage.bucketViewer`
  and `roles/storage.objectAdmin` on only the approved bucket, plus
  `roles/secretmanager.secretAccessor` on only the source-URL and encryption-key
  secrets. Do not create or download a service-account key.
- `VATA_RECOVERY_GCS_BUCKET` set to the approved bucket name.
- `VATA_RECOVERY_SOURCE_URL` supplied by a pinned Secret Manager version. It
  must be the explicitly approved PostgreSQL source; the job never falls back
  to `DATABASE_URL`.
- `VATA_RECOVERY_KEY_B64` supplied by a pinned Secret Manager version. It must
  be the base64 form of exactly 32 random bytes. The job decodes it into a
  temporary mode-`0600` key file and removes that file at exit. Keep an
  independently recoverable owner-held copy in a password manager or offline
  safe. Never put the key in the repository, build context, chat, or archive.
- Cloud Run logs in Cloud Logging only. Do not add email, webhooks, or another
  notification destination.

Run the first live job manually only after the approved source and quiescence
window are confirmed. Stop scanner, gateway, scheduler, account/team, webhook,
and direct database writers; confirm current SQLite snapshots have committed to
PostgreSQL. Download and checksum the resulting GCS object and privately record
the recovery point. Create one Cloud Scheduler job for a daily UTC run only
after that first copy is verified. Give the Scheduler identity only
`roles/run.invoker` on this Cloud Run Job. The Cloud Run Job's
`--approve-sensitive-export` argument is an operator acknowledgment, not a
substitute for owner permission.

The job emits structured success, failure, retention-cleanup, and last-verified
age records to server logs only. A failed export or checksum leaves the prior
verified objects untouched; retention cleanup is skipped until a newer copy is
verified. Cloud Scheduler delivery/attempt errors are also visible in Cloud
Logging. Review the [Cloud Storage](https://cloud.google.com/storage/pricing),
[Cloud Run](https://cloud.google.com/run/pricing),
[Cloud Scheduler](https://cloud.google.com/scheduler/pricing), and
[Secret Manager](https://cloud.google.com/secret-manager/pricing) pricing pages
for current rates and the actual archive size before relying on a total estimate.

The runtime code and deployment configuration do **not** give this repository
access to the owner's Google Cloud account. An operator must create the GCP
resources, provide secrets through Google Cloud's secure settings, verify the
first off-project copy, and confirm the scheduler is active. Live isolated
rehearsal remains a separate operation under the approval above and must follow
the restoration and tenant-isolation checks in the next section.

## Isolated restoration (never replaces the existing database)

Provision a disposable PostgreSQL server on a trusted isolated operator host
with no production application connected. Create a **new empty** database named
`recovery_<label>`. Keep network egress restricted; use synthetic identities
for routine rehearsals. Restoring a real dump needs approval and a private
environment because it contains live account data and findings.

Configure `VATA_RECOVERY_TARGET_URL` through the secure settings flow, pointing
to that local `recovery_*` database, plus the key-file path above. The tool
rejects non-loopback hosts, URL options, and existing user objects. Do not use a
tunnel, port-forward, or proxy to a production database; hostname checks cannot
distinguish one from a genuine local server.

```sh
npm run recovery:archive -- restore-isolated --approve-isolated-restore /private/recovery/downloaded.vata-dr
```

The entire encrypted archive must authenticate before `pg_restore` runs.
Decrypted staging is in a private temporary directory and removed on normal
success/failure. Use encrypted ephemeral disk on the trusted host and clean up
after an interrupted/killed process; deletion is not guaranteed secure erasure.
Restore is one transaction with exit-on-error, no `--clean`, no ownership/ACL
replay, and no fallback to another backup. Treat a dump as trusted executable SQL:
GCM integrity proves possession of the encryption key, not that an arbitrary
sender's SQL is safe.

After restoration:

1. Compare original account IDs, Clerk subjects, memberships and all PostgreSQL
   backup generations/checksums with the approved recovery point. Validate the
   complete latest SQLite payload with the existing snapshot/storage helper.
   Do not substitute a workspace SQLite file.
2. Restore SQLite into an **absent** file using the existing storage coordinator
   and a deliberate namespace. Run one isolated gateway/scanner. Keep schedules
   disabled, webhooks disconnected and Stripe mutations off during inspection.
   Do not connect production Clerk or send real scans without separate approval.
3. Authenticate two distinct owners and a team member. Check findings and
   completed/failed history for the right organization; try a conflicting
   organization query parameter. Anonymous, invalid/revoked credentials, and
   removed memberships must not expose findings. Verify genuine sign-in against
   the preserved Clerk tenant before any eventual live cutover.
4. Old backups can resurrect deleted accounts/memberships and formerly valid
   invitations/tokens. Reconcile post-backup removals, revoke/rotate API tokens
   and outstanding invitations as appropriate, rotate signing secrets, and
   recheck paid entitlements. Do not enable stale schedules automatically.
5. Record the exact recovery point, acknowledged loss window, elapsed restore
   time and checks. Obtain explicit owner approval for any future replacement.
   Production recovery/provisioning uses the platform's supported process, not
   this rehearsal command or application-startup DDL.

Never attach the original production account database to a recovered fixture
SQLite file or vice versa. Preserve evidence of corrupt/newer divergent copies
for an approved reconciliation instead of overwriting or merging tenants.

## Repeatable synthetic rehearsal and limits

```sh
npm run test:independent-recovery
```

Prerequisites match the existing storage tests: PostgreSQL server/client tools,
Python/Flask/Gunicorn dependencies, Node and npm dependencies. No skips or
workspace/production database credentials are used. Fixtures allowlist their
environment instead of inheriting application secrets.

The original small-fixture test creates two PostgreSQL **clusters**, two
synthetic account owners, a member, API-token hashes, invitations, usage,
schedules, complete SQLite data, and multiple backup namespaces. It encrypts
the full source, destroys the source cluster and SQLite file, restores to the
other cluster, compares every application table, verifies sequence continuity,
and boots built `npm start`. The real Clerk middleware validates synthetic
RSA-signed session cookies using its supported fixture public-key
configuration; no authentication bypass is added to the app. Gateway ownership
lookup, memberships, signed scanner bridge, and real Flask routes verify tenant
isolation. Invalid credentials and removed memberships are rejected. Wrong
keys, corrupt/truncated archives, unsafe destinations, overwrite attempts and
nonempty targets fail closed.

### Scaled synthetic measurement (2026-10-15)

The scaled test uses two loopback-only PostgreSQL clusters and 32 synthetic
tenants, each with an owner and a member. Each of five retained SQLite
generations contains 4 MiB of incompressible synthetic evidence per tenant.
It exports the complete encrypted PostgreSQL archive, simulates a 100 Mbps
download over loopback, verifies the transferred archive with SHA-256, removes
the source cluster and SQLite copies, and then decrypts and restores into the
isolated replacement. It opens and integrity-checks recovered SQLite and boots
the app with fixture-only authentication to verify that one owner and one
member cannot read another tenant's findings.

| Workload measure | Observed size or rate |
| --- | ---: |
| Synthetic tenants | 32 (32 owners and 32 members) |
| One SQLite snapshot | 134,402,048 bytes (128.1 MiB) |
| Five retained SQLite generations | 672,010,240 bytes (640.9 MiB) |
| Source PostgreSQL database | 705,237,475 bytes (672.7 MiB) |
| Encrypted archive | 765,952,060 bytes (730.4 MiB) |
| Verified loopback transfer throughput | 99.89 Mbps |

| Measured phase | Elapsed |
| --- | ---: |
| Full encrypted archive export (outside the recovery clock) | 86.128 s |
| Rate-limited transfer and SHA-256 verification | 61.341 s |
| Archive decryption and authentication | 9.398 s |
| PostgreSQL restore | 54.423 s |
| SQLite recovery and integrity check | 7.747 s |
| App startup plus authenticated owner/member isolation checks | 37.133 s |
| **Recovery sequence total** | **170.042 s (2 min 50.042 s)** |
| **Four-hour target** | **14,400 s** |

The recovery total starts with the rate-limited transfer and includes
decryption, PostgreSQL restore, SQLite recovery/integrity, app startup and the
two authenticated isolation checks. It excludes fixture generation, source
archive export, replacement-cluster/database provisioning, and cleanup. Archive
export is measured separately because recovery assumes a completed archive is
available to transfer.

The test process recorded a 1,600 MiB peak RSS across the run. Its Node-process
CPU samples were 17.240 CPU-seconds for archive export, 10.764 for transfer,
9.233 for combined decryption/PostgreSQL restore, 5.446 for SQLite recovery,
and 0.398 for app startup and isolation checks. These CPU and RSS samples do
not include child-process usage from PostgreSQL, `pg_dump`, `pg_restore`, or
Gunicorn; database and archive byte sizes are reported separately. The phase
timings are from this local synthetic run, not a capacity forecast.

This proves a **synthetic local disaster-recovery rehearsal**, not independent
live backup delivery, an off-site provider's durability, real Clerk sign-in,
restoration of production roles, or a four-hour production RTO guarantee.
Stripe experiments remain Preview-only. The offline production fixture verifies
subscription-free owner, API and member access without contacting Stripe.
See [Stripe test billing](stripe-billing.md) for the separate sandbox lifecycle
check and remaining browser/webhook test limits.
The download is throttled loopback HTTP, not an off-site provider, TLS/WAN path,
or production-sized storage system. The full 32-tenant dataset is seeded, but
the scaled authenticated check exercises one owner and one member; the small
fixture retains its broader authentication/denial checks. Production-sized
validation still requires an explicitly approved live rehearsal. No live
records or real Clerk/Stripe services are used or contacted by these tests.
