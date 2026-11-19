# boundary-ledger-v1

**Status:** Draft, normative
**Depends on:** [security-state-v1](security-state-v1.md), [observation-v1](observation-v1.md)
**Reference implementation:** `mcp_authscan/evidence/ledger.py`

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary ledger is the append-only history of distinct security states for **one target at one access class**. Each row links to the one before it by STATE ID, names the graded report it was produced with, and carries its own signature. It can be verified offline with SHA-256, Ed25519 and the published keys.

A target with both anonymous and authenticated captures has **two ledgers**, one per access class.

States carry no target. The ledger's **header line** names the target and access class, and appends go through observations, which carry the target. An observation for a different target or access class is **refused**, so the binding is structural and does not depend on file naming.

The ledger records **boundary changes**, not scans. A capture whose state matches the ledger head adds no row.

## 2. Format

JSON Lines: one JSON object per line, separated by `\n`, with no blank lines. The extension SHOULD be `.jsonl`.

**Line 1 is the header**, and it has exactly these keys:

```json
{"schema": "boundary-ledger-v1", "target": "<normalized URL>", "access_class": "anonymous" | "authenticated"}
```

**Every later line is a row**: a security-state-v1 object (its content keys plus `state_id` and `previous_state_id`), plus a `record`:

```json
"record": {
  "report_hash": "<64 hex>",
  "observed_at": {"start": "<RFC 3339 Z>", "end": "<RFC 3339 Z>"},
  "attestation": {"alg": "ed25519", "key_id": "<64 hex>", "value": "<unpadded base64url>"} | null
}
```

| Key | Value |
|---|---|
| `state_id` | The row's STATE ID. Chaining keys and `record` are excluded when computing it. |
| `previous_state_id` | `null` for the first row. Otherwise, the `state_id` of the row directly before. |
| `record.report_hash` | The `report_hash` of the graded report this row was produced with. It is known before the report is written, so the row always names its report. |
| `record.observed_at` | Copied from the observation. |
| `record.attestation` | An Ed25519 signature over the **row statement** (§2.1), or `null` for an unsigned row. |

### 2.1 Row statement

The attestation signs the canonical JSON (sorted keys, `,` and `:` separators, `ensure_ascii`) of:

```json
{"schema": "boundary-ledger-row-v1", "target": <header.target>, "access_class": <header.access_class>,
 "state_id": ..., "previous_state_id": ..., "report_hash": ..., "observed_at": {...}}
```

So a row is checkable **on its own**: it holds the full state, and under the signer's key it says which target, which class, which state, which position in the chain and which graded report. That holds even if the report is lost, so the chain is self-contained.

A row MAY travel outside its ledger, inline in a report as `prior_row` (EVIDENCE.md §1.1). To verify a travelling row, rebuild the header `{schema, target, access_class}` from its context. Then check the row's structure, check that its `state_id` matches its content and that its class matches, and verify its attestation (`verify_row`). Chain checks need the ledger.

### 2.2 Signed and unsigned rows

A row whose attestation is `null` is **unsigned**. Nothing attests to it. It is structurally valid, so local tooling can record it, but it **MUST NOT satisfy a delta** (boundary-delta-v1 §2.2). The reference scanner writes rows only for `--sign` runs, unless `--ledger-unsigned` is given for local use.

## 3. Append rules

An append takes an observation-v1 `O` wrapping state `S`, the graded `report_hash`, and optionally a signing key. With ledger head `H` (`null` for a header-only ledger):

1. Verify `O` (observation-v1 §5).
2. `O.target` MUST equal the header's `target`, and `S.access_class` MUST equal the header's `access_class`. If either differs, **refuse**.
3. Compute `id = STATE_ID(S)`. If `id == H`, **do not append**.
4. Otherwise, build the row (`state_id = id`, `previous_state_id = H`, `record`), sign its row statement, and write it as a new final line.

Lines MUST NOT be modified, reordered or deleted. A STATE ID MAY occur more than once, for example A → B → A.

An append MUST be **atomic and serialized**. The reference implementation holds an exclusive lock on `<ledger>.lock` across read, verify and append. It writes the whole new ledger to a temporary file, fsyncs it, and renames it over the old one. A crash therefore leaves either the previous ledger or the new one, never a partial line, and two concurrent appends cannot fork the chain.

When one run records several classes, the append MUST be **all or nothing** across them. Every new ledger is written and fsynced to a temporary file first, and only then is each renamed into place. If any row can't be written, no row lands.

## 4. Offline verification procedure

```
header := line 1; require keys {schema, target, access_class}, schema == "boundary-ledger-v1",
          target normalized, access_class valid      # fail: line 1
prev_id := null
for each line n >= 2:
    row := JSON-parse(line)                            # fail: malformed JSON
    require row.record well-formed                      # fail: record
    state := row minus record; validate against security-state-v1 (state_id must match content)
    require row.previous_state_id == prev_id           # fail: chain broken / reordered / row removed
    require row.state_id != prev_id                    # fail: no-op append
    require row.access_class == header.access_class    # fail: row class differs from header
    if published keys are supplied and row.record.attestation != null:
        require Ed25519 verify(row statement)          # fail: SIGNATURE INVALID / UNKNOWN KEY
    prev_id := row.state_id
accept; ledger head := prev_id
```

The verifier SHOULD report the failing line number and which check failed.

## 5. What verification proves, and what it does not

**Proven:**

- Each row's content matches its own STATE ID.
- The rows form one unbroken sequence at one access class. No row was removed from the middle, inserted or reordered, *relative to the file as presented*.
- With keys: each signed row was attested by a published key, for that target, class, chain position and graded report.

**Not proven:**

- **Truncation.** Cutting rows off the end still leaves a valid ledger. Detect it by comparing against a head named elsewhere: a later signed report's `ledger_head`, or a passport.
- **The header itself is not signed.** It is bound row by row instead, because each row statement repeats the target and class.
- **Unsigned rows** attest to nothing (§2.2).
- **Cross-class exposure.** The two ledgers of one target are never compared with each other. See [EVIDENCE.md §4](EVIDENCE.md#4-known-limits).
- **Truth.** The ledger shows consistency and attestation, not correctness.
