# Verified web release

The old production release freshly compiled an older frontend even though its
recorded Git commit contains the assessment routes. Its log recorded 106 modules,
the old HTML template, and `index-CMlvS7QU.js`; the workspace compiled 115 modules
and the assessment pages. A Git label alone did not describe the staged bytes.
The platform's underlying staging discrepancy has not been established.

## Build and deployment contract

`npm run build` now uses `scripts/build-web.mjs`. It resolves the project directory
from the script location, explicitly selects the Vite configuration and frontend
root/output, and cleans only the generated `build/` directory. It verifies:

- Actual source files and route/router bindings, before compilation.
- Both assessment components in Vite's rendered module graph.
- The inquiry module in esbuild's input graph and the mounted POST handler in
  the generated server, not just matching text in an unused source file.
- Both routes, both prices, and the unchanged $49 outbound link in emitted JS.
- The homepage HTML template, referenced entry asset, and every output checksum.
- Unchanged source between preflight and compilation completion.

The private `build/release-manifest.json` records the source inventory and its
SHA-256 fingerprint, graph evidence and artifact hashes. It is an integrity
record, not an authenticity signature. It contains no environment values,
customer records, credentials, or inquiry contents.

The saved next-publish command is `node scripts/deployment-web.mjs <fingerprint>`.
The independently saved expected fingerprint binds the build to approved
workspace bytes, not merely whatever a stale snapshot contains. It is checked
before package installation or compilation. A snapshot without the new entry
file fails immediately. A source mismatch logs file hashes, never file contents.
There is no fallback to old artifacts and no bypass switch.

The production Node entry also verifies the release before importing the gateway
or opening any database/scanner connection. Existing database-required checks,
writer ownership, startup health, authentication and billing behavior remain.

## After intentional source changes

Run `npm run typecheck`, `npm run build`, and `npm run test:web-build`.
Obtain the new fingerprint with `npm run --silent build:fingerprint`. Update the
saved next-publish build command's argument to that approved fingerprint, keeping
the deployment type, run command, production ports, and data settings unchanged.
This explicit approval is necessary: a fingerprint pinned to previous source
must reject a later edit rather than quietly building different input.

No runtime secrets or customer database files are fingerprinted. Production
inquiry setup remains separate; `onboarding@resend.dev` is still development-only.

## Verification and publishing

Tests use copies of source and generated artifacts in temporary directories.
They deliberately remove routes/modules/handlers, replace old HTML/client
content, change an artifact checksum, omit the manifest, and supply stale or
missing fingerprints. A separate test builds from a different working directory.
No production data, scans or emails are used.

Run the saved deployment command locally to exercise the complete package/build
path, then restart only Preview. Do not publish without owner approval. On the
next approved publish, require `deployment_source_verified`, `web_build_verified`
and `web_release_verified` with the approved fingerprint. Check live route
rendering, the HTML's actual JS asset and inquiry-status JSON, not HTTP 200 alone.
If the platform still stages different files, the pinned command must fail;
compare its logged inventory with the approved manifest instead of changing data
settings, resetting Git, or treating another generic successful build as proof.
