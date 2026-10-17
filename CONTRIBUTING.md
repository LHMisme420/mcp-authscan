# Contributing to mcp-authscan

## Authorization first

Before anything else, read the **"Authorization — read before you scan"**
section of the [README](README.md). This tool sends probe traffic; only point
it at systems you operate or are explicitly authorized to test. Contributions
that add exploit code against specific real third parties will not be accepted —
use synthetic or local targets (see `research/mcp_stdio_rce/`).

## Dev setup

```bash
pip install -r requirements-dev.txt   # ruff, mypy, coverage + runtime deps
pip install -e .                      # the mcp-authscan CLI
```

## Before you open a PR

Run the same gates CI enforces on the scanner package:

```bash
ruff check mcp_authscan research          # lint
mypy mcp_authscan                         # types
coverage run -m unittest \
  tests.test_cors_policy \
  tests.test_fixture_detections \
  tests.test_cli_enterprise \
  tests.test_stdio_rce_research
coverage report                           # must stay >= 80%
```

All four scanner suites are loopback-only and need no network access. The
web-app (flask/TS) suites are run separately.

## Conventions

- Keep detections **evidence-based** and non-exploitative: a check should prove
  a condition, not weaponize it (see `mcp_authscan/rce_checks.py` for the
  pattern — detect the precondition, never register/execute/exfiltrate).
- New checks come with a regression test that asserts the finding fires on a
  vulnerable local fixture **and** stays clean on a hardened one.
- Branch off and open a PR against `main`; CI (lint, types, tests+coverage,
  self-scan, ground-truth) must be green before merge.
