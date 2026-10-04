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
