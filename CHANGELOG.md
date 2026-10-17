# Changelog

All notable changes to the `mcp-authscan` scanner are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project
aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Source-scan suppressions for known-good patterns: an inline
  `# authscan:ignore [RULE ...]` directive (on the finding line or the line
  above; bare form suppresses all rules there) and a repo-level
  `.authscan-ignore` file of `path-glob[:RULE,...]` entries.
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
- Source scanner precision: the heuristic "surface" rules (A4 SSRF, A5, B3, and
  medium-confidence B1) now emit at **INFO / needs-review** instead of
  MEDIUM, so a pattern match never reads as a confirmed vulnerability and never
  trips `--fail-on`. Definitive detectors (A1–A3, explicit-skip and
  plain-downgrade B1, …) keep their severity and still gate.
- A4 SSRF is now sink-first with far less noise: skips generated `.d.ts`
  declaration files and `scripts/` tooling; suppresses URLs built from env
  bindings (`env.X`, `process.env`, `getenv`/`os.environ`), named config vars,
  or ALL-CAPS constants; recognizes OAuth-client token requests (PKCE verifier /
  singular `grant_type` / form-urlencoded body) as non-SSRF; and the guard check
  now understands URL-schema validation (`SomeUrl.parse(...)`), manual-redirect,
  and named validators — including guards inside arrow-function consts. A
  DCR-registration POST (`grant_types` plural, JSON body) still fires.
- B1 PKCE: the "verifier received but never validated" finding is suppressed for
  OAuth proxies/clients that forward the verifier upstream
  (`finishUpstream`/`beginUpstream`/outbound token request) rather than acting as
  the authorization server. Verified against cloudflare/mcp (15 findings → 1
  by-design INFO) with the detector benchmark holding precision/recall and the
  repo pinned as a negative fixture.

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

### Removed
- Exploit/recon scripts and result artifacts targeting specific named third
  parties, which contradicted the project's authorization stance.

## [1.0.0]
- Baseline: MCP auth/CORS scanner with text/JSON reports and CWE/OWASP/NIST
  compliance mappings.
