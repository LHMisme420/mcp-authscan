# Dependency security constraints

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
