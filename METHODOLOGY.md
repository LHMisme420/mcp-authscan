# mcp-authscan: methodology and validation

A static detector for **authentication- and authorization-logic** vulnerabilities in
Model Context Protocol (MCP) servers, gateways, and self-rolled OAuth implementations.
Part of the VATA program ("Receipts Over Promises"): every rule is seeded from a
vulnerability that was live-reproduced before the rule was written.

## Why this exists

Mainstream SAST tools model generic code hazards (injection, hardcoded strings,
bind-all) but not OAuth/authorization *semantics*. The MCP ecosystem has shipped a
recurring class of auth-logic bugs — PKCE accepted but never enforced, authorization
codes with no expiry, issuer/redirect_uri never validated, tenant isolation missing,
authentication disabled by default — that those tools structurally miss. mcp-authscan
targets that class.

## Detector taxonomy

- **A-series** — authorization/control failures: OAuth authorize handler that reads but
  never validates redirect_uri/client_id (A1); hardcoded default credentials (A2);
  authentication validated but no role/tenant/scope enforced (A3); method-scoped
  authorization bypassable on other methods (A6); cross-tenant unscoped list when a
  tenant-scoped sibling exists (A7); FastMCP server on a network transport with
  authentication disabled by default (A10).
- **B-series** — OAuth token lifecycle: PKCE accepted but not enforced (B1);
  authorization code never invalidated / no expiry (B2); code lifetime far exceeding
  RFC 6749 guidance (B3).
- **C-series** — client issuer/resource binding: MCP OAuth client built without issuer
  binding (C1/C2/C3).
- **Review-list rules** (A4/A5/B2) enumerate attack surface for human triage and are
  **excluded from precision scoring**.

## Validation — three independent pillars

### 1. Pinned labeled benchmark
Each test repository is frozen at a commit SHA, so results are reproducible and survive
upstream patching. The set contains known-vulnerable repositories (positives),
repositories audited and cleared by hand (negatives), and a latent case (pattern present
but unreachable). Precision is measured only on detector findings; review-list findings
are never counted as false positives. The harness emits a `report_sha256` over its
results, suitable for the VATA chain-of-custody anchoring workflow — the tool's metrics,
not only its findings, can be made tamper-evident.

Current result on the maintained tree: **Precision 1.00 / Recall 1.00 / F1 1.00**, with
a companion regression check confirming all seed findings still fire (11/11).
Enforced in CI on every push.

### 2. External ground truth
A separate probe runs the scanner against MCP/OAuth advisories filed by **other**
researchers, pinned at their pre-fix commit. This set is deliberately not seeded from
VATA findings — it measures whether the detectors generalize beyond what they were
written against. A "catch" requires a finding at the advisory's root-cause file.

Current: **2/3**.
- CATCH — GHSA-73cv-556c-w3g6 (mcp-pinot, FastMCP auth disabled by default), caught by
  rule A10, which was authored from this third-party advisory.
- CATCH — CVE-2025-4144 (cloudflare/workers-oauth-provider, PKCE plain-downgrade), caught
  by rule B1c, authored from this third-party advisory.
- MISS — GHSA-qx49-fqc8-xw99 (modelcontextprotocol/python-sdk, issuer validation skipped
  in a 404 discovery fallback): a conditional logic bug requiring dataflow, not a lexical
  construction. Roadmap.

The misses are published as the roadmap, each tied to a real CVE/GHSA; the tracker is
expected to start below 100% and move toward it as coverage improves.

### 3. Differential coverage
Established general-purpose SAST tools run over the **same pinned corpus**. "Caught"
means a finding at the actual vulnerable file; generic/adjacent patterns are recorded as
such. On the Python detector-positives, a mainstream Python SAST tool (bandit) caught
**0** of the auth-logic bugs while emitting 347 and 996 findings on two targets
respectively — almost entirely generic false positives (binding to 0.0.0.0, string
literals resembling passwords). It flags adjacent patterns and never models the
OAuth/authz semantics. The same harness runs gosec (Go) and semgrep (multi-language);
the completed matrix is in DIFFERENTIAL.md.

## Reproducibility
All corpora are commit-pinned; all harnesses are in `tests/` and runnable by a third
party with no access to the author. The benchmark and regression checks gate CI. A clean
checkout reproduces the reported numbers.

## Honest limitations
- Solo-maintained research tool; direct-to-main by design, branch protection restricts
  force-push/deletion only.
- Two external advisories remain uncaught (above); one wants AST/dataflow analysis that
  lexical matching cannot do precisely.
- Pattern matching has a precision ceiling: one benchmark case (header-trust present but
  not wired to a vulnerable sink) is tolerated as latent rather than flagged.
- OpenSSF Scorecard (6.4/10) measures repository hygiene, not detection accuracy; the
  detection grade is the benchmark, external probe, and differential above.

## Provenance
Findings are live-reproduced before disclosure and filed through coordinated channels.
Each detector rule carries a `VATA:` tag linking it to its seed finding.
