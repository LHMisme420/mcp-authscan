---
name: SQLite writer deployment handoff
description: Approved frontend-first writer handoff and safeguards for manual recovery.
---

The owner explicitly approved frontend-liveness-first startup to break the
publishing dependency between a new healthy root page and the old writer's
shutdown. A candidate may serve the frontend while boundedly retrying the writer
lock, but health readiness and all scanner-dependent APIs must remain 503 until
ownership, restored data, scanner initialization and snapshot verification succeed.

**Why:** Deployment probes targeted the root page. Requiring writer ownership
before listening prevented promotion from triggering old-revision drain. The
owner chose a brief honest API-unavailable interval over a startup deadlock,
without accepting concurrent SQLite writers or losing findings durability.

**How to apply:** Permit overlapping non-writing frontend startup, not overlapping
writers. Initialize SQLite and start schedules only after ownership and restore.
Never retry into readiness after an acquired lock is lost: that remains
fail-closed. Frontend 200 is deliberately not proof of writer readiness.
Verify the new release's ready event and health response after a real publish;
isolated handoff tests cannot guarantee platform shutdown timing. Persistent
contention must time out, not trigger lock theft, local-only fallback, reseeding,
namespace changes or deletion. Migrating findings to PostgreSQL remains separate
scope; this approval changes the startup contract, not the storage model.

Legacy startup that gates listening on the writer lock still requires
stop-before-start recovery. A seeded namespace and passing workspace tests alone
do not establish that a production replacement can acquire the lock.

Require a single deployment instance and preserve the SQLite database and its
WAL/journal files during recovery. A machine cap does not replace stopping the
previous revision.

**Why:** The owner explicitly requires single-writer recovery without local-only
startup, deleted database files, reseeding, or namespace changes.

**How to apply:** Configure the single-instance limit before the replacement.
Only if the writer lock persists after a confirmed full stop, the owner authorizes
terminating the lingering old gateway's backend on the production primary.
Identify that exact lock-holding session first; never terminate unrelated
sessions or infer primary lock ownership from the read replica.

Do not use the production SQL runner's `pg_locks` count to certify writer release.

**Why:** This runner connects to a read replica (`pg_is_in_recovery()` is true).
Its advisory-lock view does not describe the live primary's writer sessions.

**How to apply:** Check the connection's recovery status before interpreting
session or lock metadata. Zero replica locks are not evidence that stopping or
pausing the published writer succeeded; require primary-side or runtime shutdown
evidence instead. The Publishing UI exposes distinct Pause and Unpublish actions;
do not assume Pause terminates compute merely because it blocks public access.

`getDeploymentInfo().isDeployed === true` also applies when Publishing shows
Paused and Resume, with the saved domain retained. It does not establish that
the old gateway is running or owns the current lock.

**Why:** The owner showed an already-paused deployment whose pause predated the
failed replacements, while the deployment-info callback still reported deployed.
A direct uncached public request also returned VATA frontend HTML with an Express
header rather than a paused placeholder. The UI badge and public serving behavior
therefore did not establish the same runtime state.

**How to apply:** Read the actual UI state instead of asking the owner to pause
again, and check the public response before assuming a complete stop. Identify
the actual primary-side lock holder and seek runtime termination evidence;
do not infer lock ownership from deployment-record existence or public traffic.

The operator-confirmed Pause followed by another publish was tried and the
replacement still failed on the existing writer lock. Do not repeat that
sequence as a fix. Inspect the full stop/unpublish confirmation and its data
and URL consequences before asking the operator to proceed; brief-downtime
approval is not approval to delete the project or production database.

Full Unpublish followed by Publish restored service in an owner-confirmed
handoff; this is not evidence that it preserves the published URL.
Verify that the deployment service reports no active deployment between those
steps; do not treat this as permission for future outages without approval.

**Why:** The owner confirmed the live feature worked after this handoff, unlike
the earlier Pause-based attempt.

**How to apply:** Treat this as historical evidence for legacy startup recovery,
not a requirement to delete the deployment for frontend-first handoff.

The project's Unpublish confirmation is titled "Delete Published App" and
explicitly deletes the saved replit.app domain, published history, and associated
published app tiers. Do not describe that action as a URL-preserving stop.

**Why:** The owner supplied the exact confirmation while checking how to keep
the existing app link.

**How to apply:** When URL retention is required, cancel this deletion flow.
If manual full-stop recovery is needed, require a verified non-deleting stop;
if the available controls cannot provide one, report that limitation.
Do not substitute Pause, unverified compute restarts, or killing a still-running
writer's database session.
