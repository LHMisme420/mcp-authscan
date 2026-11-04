# Published GitHub source-scan verification

## Observed on 2026-11-04 (UTC)

No deployment, production configuration change, authentication bypass, or data
reset was performed during this investigation. The existing saved test API token
was used without displaying it. One successful authorized scan was added to its
organization's history.

- Published endpoint: `https://mcp-authscan.replit.app/api/scan`.
- Target: `https://github.com/ory/hydra`.
- GitHub HEAD immediately before and after the successful scan, and the actual
  local comparison clone: `4174065ffb052799890f7480f5360a877a67ffc1`.
- Request: authenticated POST with `target_url` and `authorized: true`.
- Published response: HTTP 200, completed scan, **17 findings**, **18 checks**,
  **12 critical**, **0 high**.
- Workspace source CLI, run against that comparison clone: **17 findings**,
  **12 critical**, **5 medium**.
- Subsequent authenticated reads of scan history and findings confirmed the
  completed scan and all **17 persisted findings**, with the same severities.
- Workspace source revision: `52c99b8ec65aa1bbde53a6142ab9a0d1b38d1ae0`.

The repository runner counts one successful source-analysis completion check in
addition to its failing finding checks. Thus 17 findings means 18 checks, not 17.
The target commit was sampled around the published request; the published scan
does not persist its cloned commit, so this is not an independently attested
production checkout hash. The agreement establishes current count/severity
parity, not a finding-by-finding historical comparison.

An earlier authenticated history read also found a completed Hydra scan dated
2026-10-16 with 9 findings and 10 checks. Historical counts should not be compared
without accounting for changes in both source rules and repository content.

## Deployed revision and routing evidence

Deployment metadata reported a public autoscale deployment with a successful
build. Build history's latest successful entry was created 2026-10-27 at
09:27:12Z; its build log named source commit
`22f66c3ec50bc555b03474ff0f3a521b164bdbb3`. A newer build attempt on 2026-11-04
failed because `.pythonlibs` was treated as a virtual environment without a
Python executable. The serving commit is **inferred from build history**, not
confirmed by a runtime commit endpoint. No publishing claim is made.

Inspection of that successful source snapshot showed:

1. Express `/api/scan` calls the authenticated scanner bridge.
2. The bridge forwards scan POST bodies to Flask `/api/scans/mcp`.
3. Flask selects `RepositoryScanner` for the exact `github.com` host.
4. The repository runner shallow-clones and invokes the offline source CLI.
   It does not fall back to website scanning when clone, CLI, or parsing fails.

The source rules differ between the successful build snapshot and the workspace.
CLI source-scan status messages go to stderr. Neither that difference nor
prefix-tolerant JSON parsing proves why the historical request reportedly
returned zero findings and nine checks.

Runtime searches over the available 30-day window found no invocation evidence
for that historical request. Its cause remains **unproven**; absence of matching
logs is not proof of source-scanner execution or non-execution.

## Explicit temporary failure

The first fresh scan attempt around 21:27 UTC returned HTTP 503. The production
investigation found a startup waiting for the exclusive findings-writer lock
from 21:26:52 until readiness at 21:28:46. This is consistent with the readiness
gate rejecting the request before scanner routing, although telemetry cannot
attribute that individual request to a replica. No backup failure was found in
that interval. A later fresh request succeeded with the counts above.

Do not bypass writer ownership, authentication, tenant isolation, or scan
authorization to avoid this temporary failure.

## Local verification

Repository tests live in `app_tests/test_repository_scan.py`, not `tests/`.
They exercise the real CLI with a synthetic vulnerable source file, verify that
the source is never executed, and check finding persistence and tenant isolation.
Both public scan aliases require authentication and authorization attestation.
The repository suite passed 14 tests; the account-bridge suite passed 8 tests.
The public preview landing page was also checked. The signed-in UI was not
visually verified; production verification used authenticated API requests.

Commands:

```sh
python3 -m unittest discover -s app_tests -p test_repository_scan.py
python3 -m unittest tests.test_account_bridge
```

The separate live-probe release gate
`python3 -m unittest tests.test_exit_code_fixtures` currently fails because
`mcp-authscan` distribution metadata is not installed in this workspace's Python
environment. Its expectations were not weakened. This investigation does not
certify general CLI release readiness or approval to publish.
