# Dependency security constraints

- Require Pillow 13.0.0+, Certifi 2026.10.23+, IDNA 3.20+, and Requests 2.34.2+.
  Apply these floors to both the web requirements and standalone scanner metadata;
  the JWT-only requirements must not pin an older HTTP stack. ReportLab 5.1 is
  used consistently by the web and scanner PDF paths.
  The app and JWT manifests pin the reviewed versions exactly; the distributable
  scanner keeps compatible ranges with the same patched minimum versions.
- Python 3.11 is now the minimum supported interpreter: older Pillow versions
  still have listed advisories, and patched Pillow 13 requires Python 3.11.
  The deployed interpreter remains 3.11; this does not replace the runtime.
- The explicit UV prefix installation reinstalls the resolved graph. A pip
  prefix upgrade can otherwise leave old dist-info directories alongside the
  new wheel: an installer exit code of zero alone is not proof that runtime
  metadata or the dependency audit sees the patched version.
- Require Flask 3.1.3 or newer and python-dotenv 1.2.2 or newer. The
  optional full requirements include the main requirements so an old duplicate
  Flask pin cannot downgrade the scanner.
- Do not restore `http-proxy-middleware` while it depends on vulnerable
  `braces` 3.0.3. Its latest release still has that dependency. The Clerk proxy
  uses `httpxy` directly (the same transport used by the latest middleware),
  without a glob-pattern parser. Forwarded authentication headers, raw request
  bodies, cookie headers, compression, bodyless responses, and the deployment
  edge's Content-Length requirements are covered by local HTTP tests.
- Google Cloud Storage 8 requires Node 22, but this project currently runs Node
  20. Keep its latest compatible 7.x release with a scoped `uuid` override to
  the patched 11.x CommonJS-compatible release, at least 11.1.1. Its consumers
  use the compatible v4 API; regression tests also verify the v3/v5/v6 buffer
  bounds fix. Do not force an ESM-only UUID major onto these CommonJS clients.
  Reconsider the override after upgrading the runtime and storage client
  together.

These dependency changes do not activate backups, contact cloud storage, enable
payments, migrate a database, or change authentication providers.

Checks:

```sh
npm run test:dependencies
npx tsc --noEmit
npm run test:startup
```
