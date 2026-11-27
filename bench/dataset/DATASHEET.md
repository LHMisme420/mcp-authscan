# MCP AuthScan labeled dataset

A ground-truth set of MCP authorization-server configurations, each with known
correct probe verdicts, scanned by mcp-authscan and recorded probe by probe.

## What it is

- **Cases** (`cases.json`): one configuration of the local fixture
  `fixture_oauth.py` per case, each switching on one flaw or a known
  combination (plain PKCE accepted, prefix redirect match, symmetric JWKS key,
  missing JWKS, permissive token-endpoint CORS, refused registration), plus a
  secure baseline.
- **Labels**: for each case, the verdict the configuration determines for the
  probes it affects. Labels are fixed before a run. Probes without a label are
  recorded but not scored.
- **Rows** (`results/run-*/rows.jsonl`): one row per case and probe, with the
  label, observed status, severity, limitation, exit code and the scan's
  `report_hash`.
- **Summary** (`summary.json`) and **`SHA256SUMS`** for each run.

## Case families (v2, 33 cases)

- **Single flaws** (C01, C02, C04 to C10): one fixture setting each.
- **Pairs** (C03, C11 to C14): two independent flaws. Both must be reported,
  and neither may change the other probe's verdict.
- **Masking** (C15 to C17, C21): refused registration hides client-dependent
  flaws (EXCLUDED, never PASS), while client-free flaws such as a symmetric
  JWKS key still FAIL.
- **Unmasking** (C18, C19): the same refusal with an operator client supplied
  (`MCPAUTHSCAN_CLIENT_ID`/`MCPAUTHSCAN_REDIRECT_URI`), so the hidden flaw
  becomes visible.
- **Redirect candidates** (C20, C21): registration accepts only the second
  loopback candidate, or none of them.
- **Malformed token endpoint** (C22 to C24): 501, an empty 204, or an HTML 400.
  These must never count as a pass.
- **Whole-scan** (A00 to A07): the eight answer-key fixtures, labeled by exit
  code and finding count.

Every fixture case also inherits `default_labels` (the six probes the secure
baseline passes) unless the case overrides them. This catches a flaw that
changes an unrelated probe's verdict.

## Reproduce and verify

    python3 bench/dataset/run_dataset.py        # from the repo root
    cd bench/dataset/results/run-<stamp> && sha256sum -c SHA256SUMS

Everything runs against loopback fixtures. No external system is scanned.

## Results

| Run | Scanner | Cases | Rows | Labeled hit |
|---|---|---|---|---|
| run-20261127T112901Z | 1.1.47 | 11 | 154 | 17/20 (label error, see below) |
| run-20261127T112925Z | 1.1.47 | 11 | 154 | 20/20 |
| run-20261127T113356Z | 1.1.47 | 33 | 462 | 176/176 |

## Label revisions

- **r2** (C07, C08, C09 `token-cors`): first labeled FAIL, observed
  NOT_OBSERVED. The fixture's `MISBEHAVE` mode issues tokens only to an
  authenticated registered client, while the plain token-cors probe sends no
  client credentials by contract, so NOT_OBSERVED is correct. A FAIL needs the
  attended `--acquire-token` mode. The labels were corrected, and the first run
  is kept as recorded.

## What it does not show

- The fixture imitates flaws. It is not any real product's code.
- Only probes the configuration determines are labeled: 176 of 462 rows in v2.
- A scan that writes no JSON report (exit 4, not an MCP server) is counted as
  zero findings and marked `report_emitted: false`.
- Attended modes (`--acquire-token`) and cross-tenant isolation are not covered.
- A match shows the scanner agrees with the label on this fixture. It does not
  prove the same verdict on every real server with that flaw.
