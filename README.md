![mcp-authscan logo](logo.png)

# VATA, MCP Security Scanner

[![Tracked by Cyber Toolchain](https://cybertoolchain.io/badge.svg)](https://cybertoolchain.io/tools/mcp-authscan/)

Auth scanner for live MCP servers.

VATA checks the security posture of Model Context Protocol deployments. It runs in two modes.

Live endpoint assessment (active). Given an MCP server URL, mcp-authscan sends real HTTP requests to that running server and records what comes back. It discovers the OAuth surface through RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata, then runs its declared set of nine authorization-server probes. All nine are implemented: issuer identity, resource binding, token endpoint Cache-Control, token endpoint CORS, JWKS key types, password grant rejection, PKCE S256 (pkce-s256), redirect URI exact match (redirect-uri-exact), and client authentication. PKCE S256 needs a client id and redirect URI exact match also needs that client's registered redirect URI. The scanner takes them, in order, from dynamic client registration at the advertised registration_endpoint (with a scanner-chosen loopback redirect, never fetched, tried in order http://localhost/mcp-authscan/callback, http://127.0.0.1/mcp-authscan/callback, http://[::1]/mcp-authscan/callback, moving to the next only when the server refuses the redirect with invalid_redirect_uri; before the report prints the client is deleted by RFC 7592 DELETE on its registration_client_uri when the registration returned one with a registration access token, and otherwise the scanner prints one line naming the client_id: client removal is out of scope for this tool; the registered client is never sent to the token revocation endpoint. The report states whether a client was registered, the candidates tried and the one accepted, and the client removal result; a client from the environment reads "no client was registered by this run"; the client secret and registration access token are never printed), else from MCPAUTHSCAN_CLIENT_ID and MCPAUTHSCAN_REDIRECT_URI; without either each reports EXCLUDED, with the limitation "No client_id to build an authorization request (MCPAUTHSCAN_CLIENT_ID not set)" or "No registered redirect_uri to compare against". Either also reports EXCLUDED ("No authorization endpoint") when the server metadata publishes no authorization endpoint. Both send GET authorization requests, never follow a redirect, and never request a returned Location. With `--acquire-token` (off by default) the token endpoint CORS probe first obtains a real access token through an attended authorization-code exchange with PKCE S256 (same client source): the scanner prints an authorization URL to stderr, you open it in a browser and approve, then paste back the full address the browser lands on (the loopback redirect; the page not loading is expected). The scanner checks that address against the registered redirect and the state it sent, redeems the code at the token endpoint with a hostile Origin, tests the cross-origin read on that response, and revokes the token before the report prints (RFC 7009: token, token_type_hint, client_id and client_secret, empty for a public client). If a token's revocation is not a 2xx or no revocation_endpoint is advertised, the scanner prints `[!] token revocation not confirmed` with the token type (never its value) and the server's answer, and the report says `Token Status: revocation not confirmed`; otherwise it says `Token Status: revoked`, or `Token Status: none acquired`. The token, verifier, code and pasted address are never printed or stored. An empty paste, a refusal (error=access_denied), a different redirect or a state mismatch reports NOT_OBSERVED with a named limitation; there is one prompt and no retry. Without the flag the scanner never prompts or reads stdin. See PROBE_CONTRACT.md [4].

Repository scan (static). Given a GitHub repository URL, it reads the source instead of sending requests.

## Want your own MCP server reviewed?

I run authorised, evidence-backed security reviews of MCP server deployments. You get a written report with every finding by severity, the request and response behind each one, and an explicit list of what was not tested, including probes not yet built.

Two ways in: a single-server review at $1,750, or a full assessment at $3,500 including one retest after you fix.

I only scan servers I hold written permission to test. Email lhmisme2011@gmail.com with the endpoint and who authorises it.

## Authorized use

Every scan needs an authorization basis. The CLI refuses to start without --authorized-by, --auth-basis and --contact, and that validation runs before any network call, so an unauthorized run exits 2 having sent nothing.

Only point this at systems you own or are permitted to test.

## Install

Python 3.11 or newer.

```bash
pip install mcp-authscan
```

Or from source:
```bash
git clone https://github.com/LHMisme420/mcp-authscan.git
cd mcp-authscan
pip install -e .
```

Build from source: `python3 -m build`

## Run

```bash
mcp-authscan https://api.example.com/mcp \
  --authorized-by "Your Name" \
  --auth-basis "written consent" \
  --contact "you@example.com"
```

## What a probe reports

Every probe returns one record: status, HTTP status, the response headers captured, the body sha256, whether its prerequisite was met, and its declared limitation. A FAIL cannot be constructed without a severity and the endpoint it was observed on. EXCLUDED requires prerequisite_met: false plus a named prerequisite.

Statuses are PASS, FAIL, NOT_OBSERVED, EXCLUDED and NOT_IMPLEMENTED.

- PASS: the response positively demonstrated the property.
- FAIL: the response demonstrated the property is absent or broken.
- NOT_OBSERVED: the request went out and the property was not demonstrated. A 404, 405, 5xx, timeout or HTML body is not a pass.
- EXCLUDED: a prerequisite, such as a token endpoint, a jwks_uri or a metadata document, was missing, or the target was outside the authorized scope, so the probe was not sent. The summary prints each EXCLUDED probe on its own line with its reason, e.g. `jwks-keys: No JWKS endpoint`. Token endpoint CORS also reports EXCLUDED for a 4xx token response with no OAuth error body.
- NOT_IMPLEMENTED: the probe is not built yet and sends no request. No probe in the current set reports this.

Coverage is PASS plus FAIL over the testable probes, the declared nine less any EXCLUDED (prerequisite missing, never sent). A run without client credentials excludes pkce-s256 and redirect-uri-exact, so when the other seven reach a verdict it reads 7 of 7 testable (1.00), 2 excluded, and the report names each excluded probe with its missing prerequisite. Zero testable probes give no coverage figure and exit 5. Not observed means sent and not demonstrated.

## Exit codes

- 0 clean, no FAIL at or above --fail-on (default high)
- 1 FAIL at or above --fail-on
- 2 authorization validation failed, no network requests made
- 3 target unreachable
- 4 target is not a valid MCP server
- 5 server not assessable, fewer than seven probes reached a verdict or zero testable probes
- 6 egress refused, a discovered host was not in the authorized set

A FAIL at or above the threshold outranks incomplete coverage, so a run with both exits 1.

## Validation

The negative control is run locally against the fixture on port 9002. It is not currently wired into CI: the cors-scanner-tests job does not run this fixture.

## Known limits

- The nine probes assess the authorization server. They do not test the MCP resource endpoints themselves.
- An endpoint prober cannot verify a three-party OAuth flow. Issuer binding is enforced client-side, so the probe checks what the metadata declares, not what a client will do.
- PKCE S256 and redirect URI exact match judge only the authorization response. They never follow a redirect or exchange a code, so they cannot show what a client does with the code.
- No dependency CVE check, no secrets-in-history scan.
- Source mode does not detect a hardcoded token whose value contains whitespace, such as `"Bearer <token>"` or `"Token <token>"`. The hardcoded-credential rule deliberately skips values with whitespace so error strings are not flagged. A literal like `api_key = "<token>"` is detected.
- Source mode does not detect wildcard CORS with credentials allowed (`Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`) set in code. Only the live token-cors probe tests CORS, against a running endpoint.
- Without `--acquire-token`, a server that properly requires client authentication at its token endpoint reports token-cors NOT_OBSERVED. The plain token-cors probe sends no client credentials, such a server answers 401 invalid_client, and only a 2xx token response can reach a verdict. A full token-cors verdict on such a server needs an attended `--acquire-token` run (PROBE_CONTRACT.md [4]). The converse also holds: a token-cors FAIL from a plain run means the server returned a 2xx token response to a request that carried no client authentication.
- Absence of a finding is not proof of safety.

A version string is a claim. A response from the running server is a receipt.

## Published findings

Credited reporter on GHSA-v693-3rfr-6q3q, critical DNS rebind protection bypass in microsandbox, fixed in 0.6.3.
Credited reporter on GHSA-vqqp-x5qm-5qp4, client credentials redirected to an attacker-controlled authorization server in fastmcp, fixed in 4.1.2.
Credited reporter on CVE-2026-60085, sandbox policy bypass in PraisonAI, rated high.
Credited reporter on GHSA-q8pm-q3r2-q7cg, argument injection in mcp-shell-server.

Findings from the official MCP reference servers were reported to the maintainers in October 2026 and are awaiting publication. That analysis is pinned to modelcontextprotocol/python-sdk commit 9972c21 and package 2.2.0.

## Versions

Current source version 1.1.8 (latest PyPI release 1.1.6) and probe set 2026.10.30.5 are versioned separately, so adding a probe never rewrites how a past report reads. A probe set stamp is `YYYY.MM.DD.N`, the date (America/New_York) the probe set changed plus a per-day counter; a test fails if the probe set changes and the stamp does not. Earlier date-only stamps and the four that were mis-dated are listed in CHANGELOG.md under "Probe set stamps".

## About

Independent AI security research by Leroy H. Mason, who also publishes as Elior Malak.
GitHub: LHMisme420 · ORCID: 0009-0002-3115-534X
Contact: lhmisme2011@gmail.com
