---
name: Authentication browser readiness
description: Brief screenshots can capture the app shell before Clerk finishes rendering.
---

Do not treat an empty sign-in shell or a home-page loading message in a brief
screenshot as proof that authentication is broken.

**Why:** The published app's initial snapshots showed no form, while a normal
browser with a longer loading budget rendered the complete sign-in form without
blocking JavaScript errors. The existing Clerk wiring matched the canonical
configuration and did not require changes.

**How to apply:** Confirm that authentication inputs appear after initialization
and inspect browser errors before changing Clerk packages, proxy code or managed
configuration. Rendering the form does not verify a signed-in session or a
completed scan; report those separately.
