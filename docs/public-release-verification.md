# Public release verification

Status: **Partial — authenticated production flow not verified.**

Checked on 2026-10-15 against the production URL returned by the deployment
service: `https://mcp-authscan--lhmisme2011.replit.app`.
These checks did not use workspace Preview.

## Observed results

- Deployment metadata: public Autoscale deployment, current build successful.
  This is not proof of which source revision was released.
- `GET /`: HTTP 200, React HTML shell with a root element and bundled assets.
- `/assets/index-PfW3uUSR.js`: HTTP 200, JavaScript content, 404070 bytes.
- `/assets/index-Ck0VCEkz.css`: HTTP 200, CSS content, 22723 bytes.
- `GET /health`: HTTP 200,
  `{"status":"ok","version":"3.0","dependencies":{"database":"ready","scanner":"ready"}}`.
- Signed-out `GET /api/account`, `GET /api/findings`, and
  `GET /api/scans/mcp`: HTTP 401, `{"error":"Unauthorized"}`.
- Signed-out `POST /api/scans/mcp` with an empty JSON object and no target:
  HTTP 401, `{"error":"Unauthorized"}`. No scan was initiated.
- Clerk management check reports managed authentication. No authentication
  settings were changed.
- A brief public-page screenshot captured “Loading secure workspace…”.
  This does not establish whether the sign-in form eventually renders, and is
  not evidence of a sign-in failure.

## Required to finish

Use legitimate production sign-in sessions for two test accounts belonging to
different organizations and an explicitly authorized MCP target. Do not mint
sessions through administrative APIs, use bridge tokens as a substitute for
sign-in, or bypass authentication.

1. Complete normal sign-in on the public site and confirm the dashboard loads
   without account/API errors.
2. Confirm the first test account owns the intended organization; ensure
   similarly named historical organizations are not claimed.
3. Submit an authorized MCP scan through the dashboard and observe completion.
4. Confirm scan history and any findings survive a page reload and a new
   legitimate sign-in. Distinguish session persistence from restart durability;
   the checks above do not independently prove backup or restart recovery.
5. Sign in separately as the second organization. Confirm it cannot see or
   retrieve the first organization's scan or findings, including by changing
   organization selectors or identifiers accepted by the API.
6. Record sanitized outcomes and response statuses, not credentials, session
   tokens, account personal details, or private finding contents.

No authenticated sessions or confirmed scan target were available during this
verification. Organization ownership, successful scanning, persisted results,
and cross-tenant isolation therefore remain unverified. No release, production
configuration change, or authentication bypass was performed.
