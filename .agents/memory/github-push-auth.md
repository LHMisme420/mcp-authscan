---
name: GitHub push authentication
description: Healthy source-control connection metadata does not guarantee usable Git credentials.
---

Verify source-control authorization with the actual Git operation rather than trusting a connection's healthy status.

**Why:** GitHub rejected pushes as invalid credentials even while the existing source-control connection reported healthy OAuth authorization.

**How to apply:** Use the source-control connection's automatic CLI authentication. After a credential rejection, use the integration reauthorization flow; do not inspect or print stored Git credentials, put tokens into remote URLs, or force-push to work around authentication.

Check access separately for GitHub and the Replit main-project SSH destination.

**Why:** A GitHub source-control connection does not establish access to the Replit main-project SSH remote. A readable public repository also does not prove write access.

**How to apply:** Verify the intended destination's access before preparing a merge, and do not describe a GitHub merge as a Replit main-project merge or a production release.

Do not push unpublished SQLite snapshot history just because the current tree
now ignores databases.

**Why:** Older local commits contained findings database updates even after a
later commit removed the database from tracking. Pushing that history would
still upload the private blobs.

**How to apply:** Inspect outgoing paths/history without displaying database
contents. A code-only release branch based on the fetched upstream commit can
deliver the current source tree while leaving original local history intact.
Do not rewrite or force-push the remote branch to remove historical data without
the owner's informed approval.

The generic integration reconnect card can fail for the native Git provider,
even when its OAuth context reports healthy and attachment reports already
added.

**Why:** The Git CLI credential was rejected while the generic integration UI
alternately treated the same source-control connection as active and unattached.

**How to apply:** If the reconnect card cannot open, stop retrying connector
attachment. Replit's documented recovery is **Account Settings → Git Providers
→ GitHub → disconnect/reconnect**, not the generic Connected Services page.
Then retry the Git push once. Never request a token in chat.
