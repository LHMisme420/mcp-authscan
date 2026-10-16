---
name: Finding data environments
description: Distinguishing preview data from published data when investigating missing scan results.
---

Establish whether a reported scan used the preview, published site, or command-line scanner before concluding that its findings were lost.

**Why:** Published logs showed accepted findings submissions while the workspace SQLite copy had no corresponding recent updates. Reading only the local database initially gave an incomplete picture.

**How to apply:** Inspect the relevant environment's logs and authenticated data path. Do not assume a workspace database mirrors production, silently copy findings between organizations, or issue organization tokens to bypass sign-in for investigation.
