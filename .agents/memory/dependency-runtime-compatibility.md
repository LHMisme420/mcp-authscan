---
name: Dependency runtime compatibility
description: Why dependency fixes must preserve Node runtime and CommonJS compatibility.
---

Keep security updates compatible with the deployed Node runtime and its
CommonJS consumers. Do not replace a scoped, patched dependency override with
an unsupported upstream major just to remove an override.

**Why:** The latest cloud-storage client required a newer Node runtime, while
the newest UUID majors dropped CommonJS compatibility. Either unbounded
upgrade could break recovery tooling even if an audit passed.

**How to apply:** See [dependency security constraints](../../docs/dependency-security.md)
for the maintained exception and regression checks. Revisit it when upgrading
the runtime and storage client together; do not activate backups to test it.
