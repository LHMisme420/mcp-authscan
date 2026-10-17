# Changelog

All notable changes to the `mcp-authscan` scanner are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/); this project
aims to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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
- Packaging: `pip install` no longer fails on flat-layout auto-discovery; added
  the `mcp-authscan` console entry point.
- Removed a broken `keycloak` submodule gitlink that aborted CI checkout.

### Removed
- Exploit/recon scripts and result artifacts targeting specific named third
  parties, which contradicted the project's authorization stance.

## [1.0.0]
- Baseline: MCP auth/CORS scanner with text/JSON reports and CWE/OWASP/NIST
  compliance mappings.
