# mcp-authscan

Static detector for **self-rolled-auth failure classes in MCP servers.**
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

A1–A3 are detectors: a hit is a finding to triage. A4–A5 are review-lists:
SSRF and enforcement-gap detection need dataflow, not pattern matching, so these
enumerate the surface to inspect rather than claiming a bug. Confidence labels
say which is which — read them.

## Usage

```
python3 mcp_authscan.py <path-to-repo>
python3 mcp_authscan.py <path> --json          # emits report_sha256 for anchoring
python3 mcp_authscan.py <path> --include-tests # test files skipped by default
python3 mcp_authscan.py <path> --fail-on high  # CI gate: nonzero exit on >= sev
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

## Provenance

Every scan is anchorable. `--json` emits a `report_sha256` over the findings;
anchor it to Ethereum before disclosure so the report is timestamped and
tamper-evident. That chain-of-custody is the differentiator — commodity scanners
don't give you a receipt.

Dashboard: https://lhmisme420.github.io/VATA-SCORES-0311

## Limitations

Heuristic static analysis. It flags patterns; it does not prove exploitability.
A4/A5 are review-lists by design. **Absence of a finding is not proof of safety.**
