---
name: Configuration validity and toolchains
description: Missing toolchain commands during a Replit configuration merge do not necessarily mean dependencies were removed.
---

Treat an invalid Replit configuration as a possible cause of missing toolchain
commands before changing dependencies.

**Why:** During a configuration merge conflict, Node/npm and ripgrep became
unavailable to shell commands. Their availability returned after the configuration
was resolved and validated, without reinstalling the toolchains.

**How to apply:** Check configuration validity when commands unexpectedly disappear
during a merge. Resolve and validate the configuration before attempting package
or runtime repairs.
