# mcp-authscan

Static detector for **self-rolled-auth failure classes in MCP servers**, plus
**issuer-binding gaps in MCP OAuth clients.**
Part of the VATA program — *Receipts Over Promises.*

Most MCP security scanners target AI-native failures (tool poisoning, prompt
injection, rug pulls). `mcp-authscan` targets the boring, classic web-auth
failures that keep shipping in MCP gateway code — the ones found by hand across
real repos and anchored as VATA findings. Stdlib Python 3, zero dependencies.

## Rules

| ID | Sev / Conf | Class | Type |
|----|-----------|-------|------|
| A1 | CRITICAL / HIGH | OAuth authorize handler reads `client_id`/`redirect_uri` but never validates against an allowlist (auth-bypass / open-redirect / ATO) | detector |
| A2 | CRITICAL–HIGH | Hardcoded default admin credentials; admin re-seed routines run on restart | detector |
| A3 | HIGH / MEDIUM | Auth middleware validates a token but enforces no role/tenant/scope (cross-tenant, CWE-863) | detector |
| A4 | MEDIUM / LOW | SSRF surface: outbound HTTP request to a non-literal, externally-influenced URL with no allowlist / internal-IP guard | review-list |
| A5 | LOW | `excluded_tools`/blocklist defined but enforcement unverified across surfaces | review pointer |
| C1 | HIGH / HIGH (MEDIUM when options are spread) | M2M MCP client provider built without an issuer binding: Python `ClientCredentialsOAuthProvider`/`PrivateKeyJWTOAuthProvider` without `issuer=`, TS `ClientCredentialsProvider`/`PrivateKeyJwtProvider`/`StaticPrivateKeyJwtProvider`/`CrossAppAccessProvider` without `expectedIssuer` | detector |
| C2 | HIGH / HIGH | Deprecated Python `RFC7523OAuthClientProvider` — has no issuer option, cannot be bound by config | detector |
| C3 | HIGH / MEDIUM | Issuer validation switched off (`skipIssuerMetadataValidation: true`, `verify_iss: False`, etc.) | detector |
| B1 | HIGH / HIGH | Self-rolled authorization server told to skip PKCE (`skipLocalPkceValidation: true`) with nothing else verifying the challenge (CWE-287) | detector |
| B1 | MEDIUM / MEDIUM | AS receives a PKCE `code_verifier` as input but no SHA-256/S256 transform appears in the file — verifier never checked against the stored challenge (CWE-287) | review-list |
| B2 | HIGH / MEDIUM | Authorization code redeemed at the token endpoint but never invalidated (delete/mark-used/revoke) in the same file — possible replay (CWE-294) | review-list |
| B3 | HIGH / HIGH | Authorization code issued with a lifetime far exceeding RFC 6749's ~600s recommendation (CWE-613) | detector |

A1–A3 are detectors: a hit is a finding to triage. A4–A5 are review-lists:
SSRF and enforcement-gap detection need dataflow, not pattern matching, so these
enumerate the surface to inspect rather than claiming a bug. Confidence labels
say which is which — read them.

### Why the C-series exists

Upgrading the MCP SDK does not close the client-side issuer gap. The fixed
versions only enforce issuer binding on M2M providers when the issuer is
configured; without it, pre-provisioned client secrets and signed JWT
assertions are sent to whatever authorization server the MCP server
advertises. Version-based scanners report a pass on code that is still
exposed. Refs: python-sdk GHSA-qx49-fqc8-xw99; typescript-sdk PR #2887
(SEP-2352). C1 is a call-site check: options built in another file show up
as MEDIUM-confidence review items.

A runtime proof of the C1/C2 gap - a rogue authorization server harvesting
the client's credentials across all three M2M shapes, and refusing once
issuer= is set - is in
rule_corpus/client_issuer_binding/live_repro/ (--json emits a
report_sha256 to anchor).

### Why the B-series exists

Every self-rolled OAuth 2.1 authorization server VATA has audited that
hand-rolls RFC 6749 / PKCE has failed at least one of three lifecycle
invariants; gateways delegating to an established IdP (Keycloak, Cognito, Dex)
have not. The B-series encodes the three most-repeated failures, seeded from
live-repro'd findings:

- **B1 — PKCE accepted but never enforced.** Either the provider is explicitly
  told to skip local PKCE (`skipLocalPkceValidation: true`, webrix) or a
  `code_verifier` is accepted but never hashed and compared (atrawog, akshay5995).
- **B2 — authorization code not single-use.** The code is redeemed but never
  invalidated, so it replays (webrix).
- **B3 — authorization code never expires / excessive TTL.** Codes issued with
  lifetimes orders of magnitude over the ~10-minute recommendation (atrawog, 1yr).

Honest limits, stated so findings are not over-claimed:

- B1 does **not** detect *optional* PKCE (validated when present, skippable when
  absent) — that is a control-flow property, not a pattern, and is left to manual
  review rather than guessed at.
- B2 is **same-file**: a server that invalidates its code in a separate storage
  module will be flagged here as a review item (MEDIUM), not asserted as a bug.
  Confirm the storage layer before filing.
- B3 fires only on an **explicit** excessive number tied to an authorization
  code; expiry that is simply *absent* across a schema (a cross-file absence) is
  not detected.

B1-skip and B3 are detectors; B1-verifier and B2 are review-lists, for the same
reason A4/A5 are — the certain cases are findings, the dataflow-dependent cases
enumerate surface to inspect. The confidence column says which.

## Usage

```
python3 mcp_authscan.py <path-to-repo>
python3 mcp_authscan.py <path> --json          # emits report_sha256 for anchoring
python3 mcp_authscan.py <path> --include-tests # test files skipped by default
python3 mcp_authscan.py <path> --fail-on high  # CI gate: nonzero exit on >= sev
python3 mcp_authscan.py <path> --exclude DIR   # skip a dir (repeatable)
```

## Ground truth

The rules are validated by re-detecting findings already filed and anchored by
VATA. A rule that stops re-detecting its seed finding is a regression, not a
release.

| Repo | Rule | Location |
|------|------|----------|
| lucky-aeon/mcp-gateway | A1 | `internal/gateway/auth.go` `handleOAuthAuthorize` |
| lucky-aeon/mcp-gateway | A2 | `internal/platform/config/config.go` defaults |
| lucky-aeon/mcp-gateway | A3 | `internal/gateway/auth.go` `mcpAuthMiddleware` |
| mcpjungle/mcpjungle | A4 | `internal/service/mcp/upstream_oauth.go` `RegistrationEndpoint` fetch |
| rule_corpus fixture | C1–C3 | `rule_corpus/client_issuer_binding` (bound providers must stay silent) |
| webrix-ai/secure-mcp-gateway | B1, B2 | `src/services/mcp-auth-provider.ts` (`skipLocalPkceValidation`, `exchangeAuthorizationCode`) |
| atrawog/mcp-oauth-dynamicclient | B1, B3 | `src/mcp_oauth_dynamicclient/routes.py` (1-year auth-code TTL) |
| akshay5995/mcp-oauth-gateway | B1 | `src/gateway.py` (`code_verifier` received, never validated) |

## Provenance

Every scan is anchorable. `--json` emits a `report_sha256` over the findings;
anchor it to Ethereum before disclosure so the report is timestamped and
tamper-evident. That chain-of-custody is the differentiator — commodity scanners
don't give you a receipt.

Dashboard: https://lhmisme420.github.io/VATA-SCORES-0311

## Limitations

Heuristic static analysis. It flags patterns; it does not prove exploitability.
A4/A5 are review-lists by design. **Absence of a finding is not proof of safety.**

## GitHub code scanning (SARIF)

`mcp-authscan` can emit SARIF 2.1.0 so findings surface natively in a repo's
**Security → Code scanning** tab. Each rule carries a `security-severity` score
and its CWE identifier, so GitHub renders severity and taxonomy with no extra
configuration.

Result level follows severity: CRITICAL/HIGH map to `error`, MEDIUM to
`warning`, LOW to `note` — so review-list (MEDIUM) findings surface as
warnings, not errors, in the Security tab.

```bash
# write SARIF to a file
mcp-authscan . --sarif results.sarif
```

To scan on every push/PR and upload results, drop this into a consuming repo at
`.github/workflows/mcp-authscan.yml` (identical copy shipped at
`examples/github-code-scanning.yml`):

```yaml
name: MCP auth scan
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 6 * * 1'

permissions:
  contents: read
  security-events: write

jobs:
  mcp-authscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install git+https://github.com/LHMisme420/mcp-authscan.git
      - run: mcp-authscan . --sarif results.sarif
        continue-on-error: true
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: mcp-authscan
```

`security-events: write` is mandatory for the upload. `continue-on-error` +
`if: always()` ensure findings still reach the Security tab when the scan exits
non-zero on a hit.
