# MCP AuthScan evidence: emitted artifacts and known limits

**Status:** Draft. Each artifact is specified normatively in its own schema document. This file covers what a scan actually writes, and lists every known limit in one place.

| Schema | What it is |
|---|---|
| [security-state-v1](security-state-v1.md) | What one MCP server exposes at one access class. Content-addressed by STATE ID. |
| [observation-v1](observation-v1.md) | Where, when and how a state was captured. Never hashed into the STATE ID. |
| [boundary-delta-v1](boundary-delta-v1.md) | Classification of `prev → curr` for two observations of one target. |
| [boundary-ledger-v1](boundary-ledger-v1.md) | Append-only chain of states for one target at one access class. |
| [boundary-passport-v1](boundary-passport-v1.md) | Portable proof of the current state and its lineage. Specified, not emitted yet. |

## 1. What a scan writes

A **completed live scan** writes the following. A source-code scan, or a live scan that halted, writes no evidence and its report has no `evidence` field.

### 1.1 The report's `evidence` field

```json
"evidence": {
  "scheme": "evidence-binding-v1",
  "states": [
    {"access_class": "anonymous",     "state_id": "<64 hex>"},
    {"access_class": "authenticated", "state_id": "<64 hex>"}
  ]
}
```

- `states` has one entry per access class that produced a state, sorted by `access_class`, with no duplicates. It MAY be empty, when no class produced a state.
- No other keys are allowed. A malformed binding makes the signature unverifiable, but does not affect `report_hash`.
- The binding is **signed and not hashed** (§3).

### 1.2 Files next to the report

The output directory is chosen in this order:

1. `--evidence-dir DIR`, if given;
2. otherwise the directory of `--output`;
3. otherwise `./mcp-authscan-evidence/`.

| File | Content |
|---|---|
| `<state_id>.state.json` | The security-state-v1 object, including `state_id`. It is content-addressed, so rescanning an unchanged boundary rewrites the same file with the same bytes. |
| `observation-<YYYYMMDDTHHMMSSZ>-<access_class>-<state_id[:12]>.json` | The observation-v1 envelope for that state. One per run per access class. |

All evidence files are written **before** the report. If any of them can't be written, the scan exits 4 and writes no report, so a report never names a STATE ID whose file is missing.

The ledger and passport are specified but not written by the scanner yet. `mcp_authscan.evidence.ledger.append_observation(path, observation)` appends to a ledger.

### 1.3 Which access classes are captured

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

The signature's job is authenticity. It covers the canonical JSON of `{"evidence": <binding>, "report": <canonical graded report>}`. So:

- **editing** a bound STATE ID breaks the signature, while `report_hash` still matches;
- **removing** the `evidence` field breaks the signature, while `report_hash` still matches;
- **adding** an `evidence` field to a report signed without one breaks the signature.

A report with no `evidence` field is signed over exactly the `report_hash` preimage, as before evidence existed, so older signed reports still verify. `verify_upload` returns the signed bytes as `canonical_bytes`, and the site's TypeScript verifier checks the signature over those bytes without needing to know about evidence.

## 4. Known limits

1. **The anonymous and authenticated views are never compared with each other** (boundary-delta-v1 §5). Each class has its own ledger, and a delta across classes is `ACCESS_CLASS_CHANGED` with no comparison.
   - **A gated server opening up is now caught in part.** A completed scan of a server that refuses anonymous `initialize` with 401/403 records the empty anonymous state. A later scan that finds anonymous tools gives `AUTHORIZATION_REGRESSION` (BD-R2), and a test proves it. **Not caught:** if that earlier scan halted (for example 401 with no OAuth discovery metadata) or the server was unreachable, no anonymous state exists, the first one becomes the ledger's first entry, and no delta is computed.
   - **A tool crossing from authenticated to anonymous** is reported the same as a brand-new anonymous tool. BD-R2 can't tell the two apart.

   Closing both needs one paired read across both classes of the same target. **Planned for v2.**
2. **The STATE ID is signed, not hashed** (§3). A report whose signature isn't checked gives no assurance about which states it was produced alongside. `report_hash` alone says nothing about evidence.
3. **Authenticity covers the report only.** State, observation, ledger and passport files are not signed in v1. The signed report binds STATE IDs, which are content hashes, so a state file can be checked against a signed report. Observations and ledgers can't be.
4. **Ledger truncation and wholesale rewrite are not detectable** from the ledger alone (boundary-ledger-v1 §5).
5. **Observation coverage is the scan's probe coverage.** It describes the OAuth probes of the run, not the surface capture.
6. **v1 states record exposure, not enforcement.** Audience binding, Origin validation and CORS are not part of the state.
