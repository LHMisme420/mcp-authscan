# Changelog

All notable changes to the `mcp-authscan` scanner are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project
aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Probe set stamps
`PROBE_SET_VERSION` (reported as `probe_set_version`) names the probe set that produced a report.
From 2026.10.30.1 a stamp is `YYYY.MM.DD.N`: the America/New_York date the probe set changed and a
per-day counter starting at 1, so two probe sets changed on one day get distinct stamps.
`tests/test_probe_set_stamp.py` fails when the probe set changes and the stamp does not
(fingerprints in `tests/probe_set_fingerprints.json`, computed by `tests/probe_set_fingerprint.py`).

Earlier stamps used the date alone. Five of them were mis-dated: each took the calendar day after
the previous stamp instead of the day its probe set changed. Commit times are America/New_York.

| Stamp | Commit | Committed | Change |
|---|---|---|---|
| 1.1.0 | tags v1.1.3 to v1.1.5 | 2026-10-25 to 2026-10-26 | semver-style stamp, replaced by dates |
| 2026.10.28 | d4372c9 (tags v1.1.6 to v1.1.8) | 2026-10-28 08:27 | correctly dated: resource probes hardened to four-branch verdicts |
| 2026.10.29 | 39bd45e | 2026-10-29 12:17 | correctly dated: contract rules for pkce-s256 and redirect-uri-exact |
| 2026.10.30 | 4a75f7c | 2026-10-29 13:26 | **mis-dated**: probes 7-8 take a dynamically registered client first, environment client as fallback, tokens revoked before the report |
| 2026.10.31 | a68c144 | 2026-10-29 15:40 | **mis-dated**: password-grant PASS on any named 4xx OAuth error except invalid_grant; token-cors non-verdict wording |
| 2026.11.01 | 07d77a0 | 2026-10-29 17:31 | **mis-dated**: dynamic registration asks for grant_types authorization_code and refresh_token |
| 2026.11.02 | a4612ef | 2026-10-29 18:19 | **mis-dated**: revocation always sends client_secret (empty for a public client) and a non-2xx reads "revocation not confirmed"; client removal only by RFC 7592 DELETE |
| 2026.11.03 | f1d4fb3 | 2026-10-30 02:37 | **mis-dated**, never on main or in a release: client_secret_basic (HTTP Basic, RFC 6749 2.3.1) at the token exchange, environment-client token-cors and password-grant, and revocation |
| 2026.10.30.1 | this change | 2026-10-30 | the 2026.11.03 probe set re-stamped under the new scheme; no probe changed |
| 2026.10.30.2 | commit adding this row | 2026-10-30 | [DEBUG] stderr lines (discovery endpoints, token-cache-control) only with --verbose; no verdict changed |
| 2026.10.30.3 | commit adding this row | 2026-10-30 | Elapsed Time excludes the attended --acquire-token wait on stdin; no verdict changed |
| 2026.10.31.1 | commit adding this row | 2026-10-31 | the shared 5xx rule is applied once to every oauth probe record, so a 5xx on any probe reads NOT_OBSERVED |
| 2026.10.30.4 | commit adding this row | 2026-10-30 | _apply_client_secret: one helper places the client secret for the token exchange, default token-cors and password-grant; requests and verdicts unchanged |
| 2026.10.30.5 | f707170 | 2026-10-30 | **withdrawn**: issued by f707170 for a report-arithmetic change, same probe set as .4; any report carrying .5 ran the .4 probe set. The change it was issued for: Coverage is PASS+FAIL over testable probes (in_scope - EXCLUDED), was over in_scope; JSON and text share counts.coverage(); zero testable exits 5 |

The fingerprint no longer hashes report accounting (the counts and coverage assignments in
`monolith.main`); every recorded fingerprint was recomputed without it, and the current stamp is
2026.10.30.4 again. `tests/test_probe_set_fingerprint_scope.py` checks that report-accounting edits
leave the fingerprint alone and probe logic or severity edits move it.

No release tag (v1.1.4 to v1.1.8) carries a future-dated stamp. Reports already produced keep
their stamp: read 2026.10.30, 2026.10.31, 2026.11.01 and 2026.11.02 as four successive probe sets
of 2026-10-29. The old date-only 2026.10.30 and the new 2026.10.30.1 are different probe sets.

### Terminology
- Probes 7-8 (pkce-s256, redirect-uri-exact) have **unmet prerequisites** (require 
  registered client to test), so they return EXCLUDED status. This is distinct from
  "out-of-scope" — both terms refer to tests that cannot run, but prerequisites define
  the verdict semantics (EXCLUDED, not NOT_OBSERVED) per the 2026-10-23 amendment.

### Added
- Hosted app: a per-scan **authorization attestation**. The `/api/scan(s/mcp)`
  endpoint now requires `authorized: true` and records the attestation to a
  `scan_authorizations` audit table; the dashboard adds a required "I'm
  authorized to test this target" checkbox. Prevents the hosted scanner from
  being used against systems the user doesn't own.
- Opt-in RCE-precondition checks (`--checks all`): unauthenticated MCP config
  endpoint (CRITICAL) and missing Host/Origin validation / DNS-rebinding (HIGH).
- Fleet scanning: multiple target URLs or `--targets FILE`, scanned concurrently
  with an aggregated report.
- `--fail-on <severity>` exit-code gating for CI.
- SARIF 2.1.0 output (`--format sarif`) for code-scanning dashboards.
- `-H/--header` to attach an identifying header required by some bug-bounty
  programs.
- `research/mcp_stdio_rce/`: local-only mocks, a safe detector CLI, and a lab
  guide for the OX Security MCP STDIO RCE classes.
- End-to-end detection regression suites; ruff/mypy/coverage quality gates wired
  into CI (lint, types, tests+coverage on a 3.8/3.12 matrix).
- `CONTRIBUTING.md`, `CODEOWNERS`, and an "Authorization — read before you scan"
  section in the README.

### Changed
- Source-mode JSON now writes `"coverage": null` (was `0`): no probe ran, so coverage does not apply, and null is
  the honest value. A live run with zero testable probes also writes null and exits 5. The text, HTML, SARIF and
  compliance-PDF renderers never print it (checked with a null payload); the text report prints no coverage number.

### Fixed
- Auth-finding accuracy: a `200` on an MCP path is now a zero-auth finding
  unless it is a human-facing HTML web page (SPA/docs catch-all). This fixes
  both a false positive (HTML pages flagged) and a false negative (an empty
  unauthenticated `200` no longer suppressed).
- Declared the web-app Python dependencies (`requirements-web.txt`) and added a
  CI `web-tests` job; the 52 flask-backed tests now run in CI.
- Portability: rewrote 336 `package-lock.json` `resolved` URLs that pointed at a
  Replit-internal mirror (`package-firewall.replit.internal`) back to the public
  npm registry, so `npm ci` works outside Replit. Added a CI `node-build` job
  (install, build client+server, run the self-contained TS suites); service-
  backed TS suites remain deploy-environment integration tests.
- Packaging: `pip install` no longer fails on flat-layout auto-discovery; added
  the `mcp-authscan` console entry point.
- Removed a broken `keycloak` submodule gitlink that aborted CI checkout.

### Known Issues
- **5xx Response Handling (Deferred to 1.1.7)**: When an OAuth endpoint returns
  5xx (server error), the scanner currently evaluates the response as if it
  contained a verdict. This causes probes that make HTTP requests (token-cors,
  token-cache-control, jwks-keys, password-grant, client-auth) to potentially
  publish FAIL findings about missing headers or invalid tokens when the server
  is actually unreachable or overloaded. A 5xx response cannot carry a verdict
  about CORS policy or authentication behavior. A systematic response handler
  that checks for 5xx before probe-specific logic will be implemented in 1.1.7.

### Removed
- Exploit/recon scripts and result artifacts targeting specific named third
  parties, which contradicted the project's authorization stance.

## [1.0.0]
- Baseline: MCP auth/CORS scanner with text/JSON reports and CWE/OWASP/NIST
  compliance mappings.
