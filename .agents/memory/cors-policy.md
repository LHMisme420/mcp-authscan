---
name: CORS finding policy
description: User-specified boundaries for wildcard and reflected-Origin CORS findings.
---

Do not treat `Access-Control-Allow-Origin: *` alone as a vulnerability. A wildcard finding requires sensitive user data plus cookie-based authentication or `Access-Control-Allow-Credentials: true`.

Only flag Origin reflection when sensitive data is accessed without authentication. Do not flag reflection on authenticated endpoints. Treat `401` and `403` responses as protected, with no CORS vulnerability finding.

For pure public APIs using header-based tokens, suppress or downgrade the wildcard finding; reflection alone is not a finding.

**Why:** The user requested these boundaries for the project's findings.

**How to apply:** Preserve this policy when changing any scanner entry point or severity classification. Do not restore unconditional wildcard findings, and distinguish observed or verified context from unknown context.
