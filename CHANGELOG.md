# Changelog

All notable changes to the `mcp-authscan` scanner are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project
aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
