---
name: Production SQL console
description: Operator-run import UX and snapshot ordering safeguards.
---

Use one atomic statement for operator-run imports in Replit's SQL console.

**Why:** The console ran `BEGIN` alone and showed “To run statements in a
transaction — select multiple statements and run SQL.” Repeated clicks on Run
did not execute the rest of the pasted batch. This message is a console hint,
not a PostgreSQL failure.

**How to apply:** Prefer a single SQL statement with explicit result/status
columns. Have the operator select the SQL text inside the editor before clicking
the main Run button if it appears idle, even for a single-statement import.
Verify committed production state using read-only queries afterward;
opening an instruction asset or seeing zero result rows is not proof of a seed.
The operator, not Agent's read-only production connection, executes the import.

An empty operator bootstrap must never outrank a normal committed snapshot.

**Why:** A single statement's MVCC snapshot may precede advisory-lock acquisition.
A concurrent commit can therefore be invisible to its absence check even if the
lock is acquired afterward.

**How to apply:** The empty import reserves generation zero, below normal
positive identity generations, and uses the namespace writer lock plus a
conflict-safe insert. Do not reset the identity sequence or replace existing
snapshots. Startup still never creates an empty namespace.
