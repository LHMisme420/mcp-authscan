# Changelog

## Severity calibration

- **Zero-auth severity now reflects the demonstrated surface, not the absence of auth** (calibration 2026.11.05.1). A zero-auth finding is graded by what the response demonstrated: CRITICAL only when a returned tool's name shows a write, delete, or execute action; HIGH when tools were returned but none names such an action; MEDIUM otherwise, including a response that demonstrated no tools or did not parse. Record-level data in the body is not inspected (a loose content check re-creates over-grading); the finding's `severity_basis` states what decided the grade, and the report footer names the calibration version. Previously any zero-auth response was graded CRITICAL on the absence of auth alone.
- **Severity calibration is versioned separately** (`SEVERITY_CALIBRATION_VERSION`, 2026.11.05.1), not by the probe set: the probes themselves are unchanged, so `PROBE_SET_VERSION` stays 2026.11.05.1. The calibration version is stamped in any report containing a zero-auth finding, so two reports can be compared honestly even though the same probe can now yield a different severity.
- **Behaviour change for `--fail-on critical`**: a zero-auth finding that demonstrates no write/execute surface is now MEDIUM, not CRITICAL, so a CI gate set to `--fail-on critical` that previously failed on such a finding will no longer fail on it. This is intended. Gate on `--fail-on high` (or lower) to keep failing on zero-auth findings regardless of demonstrated surface.

All notable changes to the `mcp-authscan` scanner are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project
aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Rate limiting is now probed and reported: a 429 inside the authorised budget passes, no 429 inside it is not observed, and a scan with no budget is excluded with the reason named.

### Fixed
- The probe-set stamp guard now covers the target probes as well as the OAuth set, so a CORS or rate-limit change moves the stamp test instead of slipping past it.

## [1.1.20] - 2026-11-02

### Fixed
- A live scan with no OAuth probe records no longer reports drift or content findings as failed probes. Source scans still report their findings count.

### Docs
- The OWASP coverage page no longer says the scanner cannot read tool descriptions, prompts or resources.

## [1.1.11] - 2026-11-02

### Added
- Text and HTML reports now say whether the tools/list digest was captured, and name the reason when it was not.
- The digest stays outside the report hash; it moves no verdict and no coverage count.

## [1.1.12] - 2026-11-02

### Fixed
- The User-Agent reports the installed package version instead of a hardcoded 2.0.0.

## [1.1.13] - 2026-11-02

### Changed
- The README states that ten probes run by default and that cross-tenant isolation needs MCPAUTHSCAN_CROSS_TENANT=1.

## [1.1.17] - 2026-11-02

- README: review offer moved below Versions.
## [1.1.18] - 2026-11-02

### Changed
- A halted scan now prints its report and exits 5 instead of 3 with no report.
- discovery_status is recorded in the payload and the saved report.
- Exit contract stamp is now 2026.11.02.4.

## [1.1.19] - 2026-11-02

### Fixed
- A refused tools/list capture no longer exits 6 after the scan has run, and it now uses the same allowed host set as the scan.
- The printed hash statement now names the tools_digest block among its exclusions.

## [1.1.16] - 2026-11-02

### Added
- Surface drift: a scan captures a digest of the server's tools, prompts, resources and its own instructions, then reports each item that differs from a recorded baseline as added, removed or changed.
- --surface-baseline FILE writes a baseline when the file does not exist, and compares against it when it does.
- Drift findings use rule MCPD-1 at medium severity, carrying the baseline path, the item key and the before and after text as evidence. Drift never counts as a pass and stays outside the ten OWASP categories.
- The text report states whether the surface was pinned, unchanged, changed or not compared, with the reason when it was not compared.

### Fixed
- Drift findings were written to a list the report does not read, so they were missing from the text report and the JSON payload while still appearing in the surface record.
- A scan that stopped at OAuth discovery said it was reporting content findings and then printed none. It now lists them, with evidence, before it stops.
- Installed metadata and the README still recorded 1.1.14 while the source was 1.1.15.

## [Unreleased]

### Probe set stamps

- 2026.11.10.2: preflight now records serverInfo.name, serverInfo.version and the negotiated protocolVersion from the unauthenticated initialize it already performs. NOT_OBSERVED when the response carries no result. No new request, no new host contacted.

- 2026.11.10.1: recorded a probe set change that landed between 2026-11-07 and 2026-11-10 without a stamp bump; every component recomputed from the tree at the time of recording, fingerprint e2c0850f. No PASS or FAIL verdict changed, and no past report is regraded.
- 2026.11.02.1: the User-Agent reports the installed package version; no verdict or coverage change.
- 2026.11.04.2: password-grant and client-auth report NOT_OBSERVED rather than EXCLUDED when the response carries no usable token; no PASS or FAIL verdict changed.
- 2026.11.06.1: coverage changed on a zero-auth target. The OAuth probes are now recorded as EXCLUDED with the OAuth discovery prerequisite named, instead of being dropped from the declared set, so in_scope is the full probe set and coverage stops reading 1.00 on a run that tested one endpoint. ZERO-AUTH maps to MCP07 instead of unmapped, and a category with no mapped rule reports no-probe rather than covered. The zero-auth severity basis no longer says no tools were demonstrated when the response simply carried no tool list to grade. No PASS or FAIL verdict changed.
- 2026.11.05.1: verdicts changed. jwks-keys reports NOT_OBSERVED rather than FAIL when the JWKS endpoint returns a non-2xx status, an empty body or no keys array, and records the real HTTP status instead of 200; jwks-keys FAILs when any key is symmetric (kty=oct), including mixed sets that previously passed. token-cors reports NOT_OBSERVED rather than EXCLUDED on a 4xx without an OAuth error body, and NOT_OBSERVED rather than PASS on a 2xx with an empty body; with --acquire-token it FAILs on a reflected hostile Origin (previously NOT_OBSERVED) and PASSes only when an access token was obtained. token-cache-control judges only a token-endpoint response (a 2xx carrying access_token, or a 2xx or 4xx with an OAuth error body; RFC 6749 5.1 requires no-store on token responses) and redacts the recorded body: a 5xx, a failed request or an out-of-scope URL reports NOT_OBSERVED rather than EXCLUDED, and a 2xx, an empty body or a non-OAuth response reports NOT_OBSERVED rather than PASS or FAIL.
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
| 2026.11.02.2 | commit adding this row | 2026-11-02 | no probe added or altered; the egress guard honours the allowed_hosts it is given and refuses a URL with no hostname, so what every probe may reach changed |
| 2026.11.02.3 | commit adding this row | 2026-11-02 | exit contract: no probe attempted but at least one content finding now produces a report with coverage null and exits by the findings, was exit 3 with no report |
| 2026.11.03 | f1d4fb3 | 2026-10-30 02:37 | **mis-dated**, never on main or in a release: client_secret_basic (HTTP Basic, RFC 6749 2.3.1) at the token exchange, environment-client token-cors and password-grant, and revocation |
| 2026.10.30.1 | this change | 2026-10-30 | the 2026.11.03 probe set re-stamped under the new scheme; no probe changed |
| 2026.10.30.2 | commit adding this row | 2026-10-30 | [DEBUG] stderr lines (discovery endpoints, token-cache-control) only with --verbose; no verdict changed |
| 2026.10.30.3 | commit adding this row | 2026-10-30 | Elapsed Time excludes the attended --acquire-token wait on stdin; no verdict changed |
| 2026.10.31.2 | commit adding this row | 2026-10-31 | monolith ALLOW_PRIVATE_TARGETS defaults to false, so the egress guard fails closed for callers other than main |
| 2026.10.31.1 | commit adding this row | 2026-10-31 | the shared 5xx rule is applied once to every oauth probe record, so a 5xx on any probe reads NOT_OBSERVED |
| 2026.10.30.4 | commit adding this row | 2026-10-30 | _apply_client_secret: one helper places the client secret for the token exchange, default token-cors and password-grant; requests and verdicts unchanged |
| 2026.10.30.5 | f707170 | 2026-10-30 | **withdrawn**: issued by f707170 for a report-arithmetic change, same probe set as .4; any report carrying .5 ran the .4 probe set. The change it was issued for: Coverage is PASS+FAIL over testable probes (in_scope - EXCLUDED), was over in_scope; JSON and text share counts.coverage(); zero testable exits 5 |
| 2026.10.31.3 | 38ed39d | 2026-10-31 05:50 | probe 10 cross-tenant added and parked behind MCPAUTHSCAN_CROSS_TENANT, declared set stays nine; token-cors on a plain scan EXCLUDED naming the missing client credential |
| 2026.10.31.4 | b175070 | 2026-10-31 06:01 | jwks-keys reports NOT_OBSERVED when the JWKS endpoint cannot be fetched, was EXCLUDED; a failed fetch is an attempt not observed, not a missing prerequisite |
| 2026.11.01.7 | a9b7faa | 2026-11-01 | probe 11 revokes the audience token after the presentation, so PASS means a foreign-audience token was refused rather than a revoked one; no probe added, verdict meaning changed |
| 2026.11.01.5 | bdf49d2 | 2026-11-01 | probe 6 password-grant takes the client the run resolved, falling back to the environment; no verdict changed |
| 2026.11.01.6 | dc2ebff | 2026-11-01 | probe 11 token-audience asks with the resolved client and records EXCLUDED, prerequisite named, when the token endpoint refuses the grant |

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

