# MCP AuthScan evidence: emitted artifacts and known limits

**Status:** Draft. Each artifact is specified normatively in its own schema document. This file covers what a scan actually writes, and lists every known limit in one place.

| Schema | What it is |
|---|---|
| [security-state-v1](security-state-v1.md) | What one MCP server exposes at one access class. Content-addressed by STATE ID. |
| [observation-v1](observation-v1.md) | Where, when and how a state was captured. Never hashed into the STATE ID. |
| [boundary-delta-v1](boundary-delta-v1.md) | Classification of `prev → curr` for two observations of one target. |
| [boundary-ledger-v1](boundary-ledger-v1.md) | Append-only chain of states for one target at one access class. |
| [boundary-passport-v1](boundary-passport-v1.md) | Portable proof of the current state and its lineage. Specified, not emitted yet. |
| [boundary-contrast-v1](boundary-contrast-v1.md) | Separate credentialed mode: reproducible anonymous-vs-credentialed differences against declared expectations. Specified, not implemented. |

## 1. What a scan writes

A **completed live scan** writes the following. A source-code scan, or a live scan that halted, writes no evidence and its report has no `evidence` field.

### 1.1 The report's `evidence` field

```json
"evidence": {
  "scheme": "evidence-binding-v3",
  "states": [
    {"access_class": "anonymous",
     "state_id":    "<64 hex>",
     "ledger":      "<host>_<port>-<sha16>/anonymous.jsonl" | null,
     "ledger_head": "<64 hex>" | null,
     "prior_row":   { <the head row: full state, state_id, previous_state_id, record with its own attestation> } | null}
  ]
}
```

- **`ledger`** names the chain this state was recorded in, as its key under the ledger root. It is never an absolute path, so a published report doesn't carry the scanning machine's home directory. It is `null` when no row was recorded, for example on unsigned runs (§1.3).
- **`ledger_head`** is the chain's head before this run, or `null` for a new chain. If it equals `state_id`, the boundary was unchanged and no row was added.
- **`prior_row`** is **that head row itself**, inline: the full prior state plus its `record` (`report_hash`, `observed_at`) and **its own Ed25519 attestation**. It is present exactly when `ledger_head` is, and `prior_row.state_id` MUST equal `ledger_head`. This is what turns `ledger_head` from an assertion into evidence: a reader holding only this report, the current observation and the published keys can check the prior surface and compute the delta (`evidence.delta.delta_from_report`), with no ledger file and no earlier report.
- `states` is sorted by `access_class`, with no duplicates, and MAY be empty. No other keys are allowed.
- The whole binding, `prior_row` included, is **signed and not hashed** (§3). So `prior_row` carries two signatures: its own row attestation, and the report signature over the binding. Bindings `evidence-binding-v1` (`{access_class, state_id}`) and `-v2` (no `prior_row`) are still accepted when verifying.

### 1.2 Files next to the report

The output directory is chosen in this order:

1. `--evidence-dir DIR`, if given;
2. otherwise the directory of `--output`;
3. otherwise `./mcp-authscan-evidence/`.

| File | Content |
|---|---|
| `<state_id>.state.json` | The security-state-v1 object, including `state_id`. It is content-addressed, so rescanning an unchanged boundary rewrites the same file with the same bytes. |
| `observation-<YYYYMMDDTHHMMSSZ>-<access_class>-<state_id[:12]>.json` | The observation-v1 envelope for that state. One per run per access class. |

### 1.3 Ledger rows

On **`--sign` runs**, each observation's state is recorded in the ledger for its target and access class:

```
<ledger root>/<host>_<port>-<sha256(target)[:16]>/<access_class>.jsonl
```

`<ledger root>` is chosen in this order:
1. `--ledger-dir DIR`;
2. else `$MCP_AUTHSCAN_LEDGER_DIR`;
3. else **`~/.config/mcp-authscan/ledgers`**, next to the signing key.

The default is per user and keyed only by target, so every run of a target meets the same chain whatever its `--output` path. The file name only *locates* the ledger. Its header line `{schema, target, access_class}` *binds* it, and an append for a different target or class is refused. A state equal to the head adds no row.

Each row carries the run's **`report_hash`** and its own **Ed25519 attestation** over the target, class, chain position, report hash and observation time (boundary-ledger-v1 §2.1). A row stays checkable even if its report is lost.

**Unsigned runs record no rows.** A row nothing attests to would turn the ledger into a log, with no way to tell which entries carry a signature. `--ledger-unsigned` records unsigned rows for local use. Their attestation is `null`, and a delta refuses them (boundary-delta-v1 §2.2).

### 1.4 Order and failure

1. hash
2. capture and bind
3. **lock and verify each class's ledger**, and write `ledger`/`ledger_head` into the binding
4. **sign**
5. **evidence files**
6. build and sign rows
7. **stage the report** (write `--output.tmp` and fsync it)
8. **commit every ledger row, all or nothing**
9. **rename the report into place**
10. print it

| Failure at | Exit | Report | Ledger rows |
|---|---|---|---|
| 3: ledger fails verification, header for another target or class, root unwritable | 4 | none | none; the ledger is left untouched |
| 4–6: signing, evidence files, row build | 4 | none | none |
| 7: report can't be staged (disk full, missing directory) | 4 | none | none |
| 8: any class's row can't be written | 4 | none | **none for any class** (two-phase: temp files first, renames after) |
| 9: final rename of the report | 4 | none | recorded; stderr names them |

The last row of that table is the only way a row can exist without its report, and it loses nothing the chain depends on. A row stores the **full state**, and its signature covers `state_id`, `previous_state_id`, `report_hash` and `observed_at` (boundary-ledger-v1 §2.1). So the chain is self-contained: the next run diffs against that row, and a reader can verify it without the report. What is lost is the graded findings of that one run, and the row's `report_hash` names exactly which report that was.

The passport is specified, but the scanner doesn't write it yet.

### 1.5 Which access classes are captured

| Class | Captured when | Gives a state when | Gives no state when |
|---|---|---|---|
| `anonymous` | always, with no credential | `initialize` and all three lists answered | the server wasn't reached, answered 5xx, or a list failed |
| `anonymous` | (same capture) | `initialize` answered **401 or 403**: the **empty** anonymous state | — |
| `authenticated` | `MCPAUTHSCAN_TOKEN` is set | `initialize` and all three lists answered | anything else, including a refused credential |

For the empty anonymous state, the refusal goes in the observation's `capture` field (`{"status": "refused", "reasons": [...]}`), **never in the state**. A refusal answer is a fact about the boundary: anonymous clients see nothing. A server that is down tells you nothing about the boundary, so it gets no state at all, and the reason only appears on stderr.

The empty anonymous state has STATE ID `f91b3009b031cd660ff79f978b7b6c5ac0b85530ff93e55b2c173f9cdd743f52`. A server that answers anonymously but exposes nothing, with no instructions, has the same ID, because the boundary is the same. Their observations differ in `capture.status`.

## 2. Signing

`--sign` is an assertion. The run either produces a signed report or produces no report.

- **Key:** `$MCP_AUTHSCAN_SIGNING_KEY` (a path to an Ed25519 PEM), falling back to `~/.config/mcp-authscan/report-signing.pem`.
- **Checked before any request leaves.** A missing or unusable key exits **2** with nothing scanned and nothing written. Failing to sign at the end of the run exits **4**, also with nothing written.
- **Error messages** name only the exception type. Key contents and paths never appear in reports or logs.

## 3. Why the STATE ID is signed but not hashed

`report_hash` is SHA-256 over the **graded content only**: target, status, counts, coverage and findings. Its job is reproducibility. Anyone holding the report can recompute it from the graded fields with no other data and no key. If STATE IDs were hashed, that check would depend on evidence files the verifier may not have. It would also change `report_hash` whenever the surface changed, even when the grading didn't.

The signature's job is authenticity. The bytes it covers are chosen by the report's top-level **`sig_version`**, which is outside `report_hash`. A verifier reads it; it never infers the form from which fields happen to be present:

| `sig_version` | Signed bytes | `evidence` |
|---|---|---|
| absent (every report signed before `sig_version` existed) or `1` | canonical graded report: exactly the `report_hash` preimage | MUST be absent |
| `2` | canonical JSON of `{"sig_version": 2, "evidence": <binding>, "report": <canonical graded report>}` | MUST be present |

Any other value, or a mismatch between `sig_version` and `evidence`, means authenticity can't be verified: the verifier reports `DIVERGENCE` (the declared signed content cannot be rebuilt) or `UNSUPPORTED FORM` (an unknown `sig_version`) while integrity stays `INTACT`. The scanner always writes `sig_version` when it signs: `2` when evidence is bound, `1` otherwise. So:

- **editing** a bound STATE ID breaks the signature (`SIGNATURE INVALID`), while `report_hash` still matches;
- **removing** `evidence` or `sig_version` from a form-2 report, or downgrading it to `1`, makes authenticity unverifiable, while `report_hash` still matches;
- **adding** `evidence` to a form-1 report is refused: form 1 doesn't cover it, so unsigned evidence can never ride on a valid signature.

Old reports without `sig_version` keep verifying unchanged. Every verifier (the CLI, the site through `verify_upload`, and the policy gate) gets its verdict from one engine, `mcp_authscan.verification`, which rebuilds the bytes of the declared form with `report_verify.signed_content` and checks the Ed25519 signature against the pinned key history (`mcp_authscan/key_history.json`). The Node server does not verify signatures. `tests/test_evidence_signing.py` runs the engine and the site adapter on a real signed report that carries evidence.

## 4. Known limits

1. **The anonymous and authenticated views are never compared with each other** (boundary-delta-v1 §5). Each class has its own ledger, and a delta across classes is `ACCESS_CLASS_CHANGED` with no comparison.
   - **A gated server opening up is now caught in part.** A completed scan of a server that refuses anonymous `initialize` with 401/403 records the empty anonymous state. A later scan that finds anonymous tools gives `AUTHORIZATION_REGRESSION` (BD-R2), and a test proves it. **Not caught:** if that earlier scan halted (for example 401 with no OAuth discovery metadata) or the server was unreachable, no anonymous state exists, the first one becomes the ledger's first entry, and no delta is computed.
   - **A tool crossing from authenticated to anonymous** is reported the same as a brand-new anonymous tool. BD-R2 can't tell the two apart.

   Closing both needs one paired read across both classes of the same target. **Planned for v2.**
2. **The STATE ID is signed, not hashed** (§3). A report whose signature isn't checked gives no assurance about which states it was produced alongside. `report_hash` alone says nothing about evidence.
3. **What is signed.** The report (graded content plus the evidence binding, including each chain's `ledger` key and `ledger_head`) and each ledger row (its row statement) are signed. State and observation files are not. A state file can be checked against a signed report or row by its STATE ID, and an observation file can't be checked at all. The ledger **header** isn't signed, but every row statement repeats its target and class.
4. **Ledger truncation is not detectable from the ledger alone** (boundary-ledger-v1 §5). It is detectable against any later signed report whose `ledger_head` names a row that's missing. A rewrite would need the signing key, because every row is attested.
7. **A row can outlive its report** only if the final rename of the report fails after the ledger commit (§1.4). The chain stays self-contained, because the row holds the full state and is signed. Only that run's graded findings are lost, and its `report_hash` is named.
9. **The current state is bound, not inlined.** A report carries the *prior* head row inline, but only the *current* state's ID. Computing a delta from a report also needs the current observation or state file, which is checkable against the signed `state_id`.
8. **The default ledger root is per user.** Two users on one machine, or two machines, keep separate chains for the same target unless they share `--ledger-dir` / `$MCP_AUTHSCAN_LEDGER_DIR`.
5. **Observation coverage is the scan's probe coverage.** It describes the OAuth probes of the run, not the surface capture.
6. **v1 states record exposure, not enforcement.** Audience binding, Origin validation and CORS are not part of the state.
