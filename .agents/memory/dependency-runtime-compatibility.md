---
name: Dependency runtime compatibility
description: Why dependency fixes must preserve runtime compatibility and portable lockfile URLs.
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

## Portable lockfile download locations

Keep committed tarball URLs portable HTTPS registry addresses, without changing
the selected package versions, integrity hashes, or active installation
security controls.

**Why:** The managed package installer can rewrite lockfile download locations
to an HTTP workspace-internal mirror. An installation inside Replit can pass
while clean installs in external CI or recovery builders become unreachable.

**How to apply:** Inspect lockfile URL changes after managed package updates.
Normalize internal-mirror metadata to the corresponding public HTTPS tarball
URLs without disabling the Package Firewall or changing installation registry
configuration. Verify the real clean-install build preserves the normalized
lockfile and the patched dependency versions.
