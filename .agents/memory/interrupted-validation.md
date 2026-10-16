---
name: Interrupted validation
description: Distinguish stale completion results from failures in the current implementation.
---

After a user interrupts a completion attempt and redirects implementation,
check validation-log timestamps and the current code before acting on a
returned failure or review.

**Why:** A completion call returned results from an earlier exact file
replacement after the user had authorized an adaptation. The old review
reported missing routes that were already restored, and its dependency error
predated a successful dependency installation and local startup checks.

**How to apply:** Read the named logs, compare their timestamps with the current
revision, and confirm the specific reported routes or dependencies. If the
results describe the earlier snapshot, submit the current implementation for
fresh validation instead of undoing working changes or claiming the old
failure was reproduced.
