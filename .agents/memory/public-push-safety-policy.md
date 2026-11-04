---
name: Public push safety policy
description: Source-only publication checks must preserve private local history and not exempt test folders wholesale.
---

Keep public-push checks read-only and explicit about the outgoing branch and destination. Do not automatically install hooks, upload private backup branches, rewrite history, delete local data, or force-push as remediation.

**Why:** The owner requested a reusable safety check while keeping local databases and unpublished history intact.

**How to apply:** When adding publication automation, preserve the source-only release approach and get separate approval for any automatic enforcement. Inspect all outgoing commits, not merely a clean final tree. Allow only narrow dummy credential values, not blanket exemptions for test directories, because real credentials can be committed there too.
