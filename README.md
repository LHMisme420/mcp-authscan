# VATA, MCP Security Scanner

Receipts over promises.

VATA checks the security posture of Model Context Protocol deployments. It runs in two modes.

Live endpoint assessment (active). Given an MCP server URL, mcp-authscan sends real HTTP requests to that running server and records what comes back. It discovers the OAuth surface through RFC 9728 protected-resource metadata and RFC 8414 authorization-server metadata, then runs nine authorization-server probes: issuer identity, resource binding, token endpoint Cache-Control, token endpoint CORS, JWKS key types, password grant rejection, PKCE S256, redirect URI exact match, and client authentication.

Repository scan (static). Given a GitHub repository URL, it reads the source instead of sending requests.

Both are available in the hosted workspace at mcp-authscan.replit.app and through the CLI.

## Authorized use

Every scan needs an authorization basis. The CLI refuses to start without --authorized-by and --auth-basis, and that validation runs before any network call, so an unauthorized run exits 2 having sent nothing. The hosted API requires an explicit attestation (authorized: true) and records it in scan_authorizations before a scan runs.

Only point this at systems you own or are permitted to test.

## Install

Python 3.11 or newer, including for the standalone scanner.

```bash
git clone github.com/LHMisme420/mcp-authscan.git
cd mcp-authscan
pip install -e ./mcp_authscan
```

Packaging metadata lives in mcp_authscan/pyproject.toml; the repository root is the web project. Build distributions with python -m build ./mcp_authscan --outdir ./dist.

## Run

```bash
mcp-authscan api.example.com/mcp \
  --authorized-by "Your Name" \
  --auth-basis "written consent" \
  --contact "you@example.com"
```

## What a probe reports

Every probe returns one record: status, HTTP status, the response headers captured, the body sha256, whether its prerequisite was met, and its declared limitation. A FAIL cannot be constructed without a severity and the endpoint it was observed on. EXCLUDED requires prerequisite_met: false plus a named prerequisite.

Statuses are PASS, FAIL, NOT_OBSERVED and EXCLUDED.

- PASS: the response positively demonstrated the property.
- FAIL: the response demonstrated the property is absent or broken.
- NOT_OBSERVED: the request went out and the property was not demonstrated. A 404, 405, 5xx, timeout or HTML body is not a pass.
- EXCLUDED: the probe was never sent because a prerequisite, such as a registered client, was missing.

Coverage is PASS plus FAIL over the in-scope set after exclusions. Excluded means never sent. Not observed means sent and not demonstrated.

## Exit codes

- 0 clean, no FAIL at or above --fail-on (default high)
- 1 FAIL at or above --fail-on
- 2 authorization validation failed, no network requests made
- 3 target unreachable
- 4 target is not a valid MCP server
- 5 server not assessable, coverage incomplete or zero testable probes
- 6 usage error

A FAIL at or above the threshold outranks incomplete coverage, so a run with both exits 1.

## Validation

A negative control runs in CI as cors-scanner-tests: a deliberately bad fixture reports 1 finding, cors_origin_credentials_reflection, with four endpoints in evidence, and the good fixture reports 0.

## Known limits

- The nine probes assess the authorization server. They do not test the MCP resource endpoints themselves.
- An endpoint prober cannot verify a three-party OAuth flow. Issuer binding is enforced client-side, so the probe checks what the metadata declares, not what a client will do.
- PKCE S256 and redirect URI exact match need a registered client and report EXCLUDED without one.
- No source review, no dependency CVE check, no secrets-in-history scan.
- Absence of a finding is not proof of safety.

A version string is a claim. A response from the running server is a receipt.

## Published findings

Credited reporter on GHSA-v693-3rfr-6q3q, critical DNS rebind protection bypass in microsandbox, fixed in 0.6.3.
Credited reporter on GHSA-vqqp-x5qm-5qp4, client credentials redirected to an attacker-controlled authorization server in fastmcp, fixed in 4.1.2.
Credited reporter on CVE-2026-60085, sandbox policy bypass in PraisonAI, rated high.
Credited reporter on GHSA-q8pm-q3r2-q7cg, argument injection in mcp-shell-server.

Findings from the official MCP reference servers were reported to the maintainers in October 2026 and are awaiting publication. That analysis is pinned to modelcontextprotocol/python-sdk commit 9972c21 and package 2.2.0.

## Versions

Tool version 1.1.3 and probe set 1.1.0 are versioned separately, so adding a probe never rewrites how a past report reads.

## About

Independent AI security research by Leroy H. Mason, who also publishes as Elior Malak.
GitHub: LHMisme420 · ORCID: 0009-0002-3115-534X
Contact: lhmisme2011@gmail.com
