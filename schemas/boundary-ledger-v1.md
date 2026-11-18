# boundary-ledger-v1

**Status:** Draft, normative
**Identifier:** `boundary-ledger-v1`
**Depends on:** [security-state-v1](security-state-v1.md)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary ledger is the append-only history of distinct security states for **one target**. Each entry links to the one before it by STATE ID. The ledger can be verified offline with nothing but SHA-256 and the canonicalization rules in security-state-v1 §5.

The ledger records **boundary changes**, not scans. A scan whose state matches the ledger head does not add an entry. Its evidence goes in an [observation-v1](observation-v1.md).

## 2. Format

A ledger is a UTF-8 text file in **JSON Lines** format: one JSON object per line, lines separated by `\n`, no blank lines. The file extension SHOULD be `.jsonl`.

Each line is a security-state-v1 object that **MUST** carry both chaining keys:

| Key | Value |
|---|---|
| `state_id` | The STATE ID of this entry, computed per security-state-v1 §5. Computing it excludes `state_id` and `previous_state_id` themselves. |
| `previous_state_id` | `null` for the first entry (genesis). For every later entry, the `state_id` of the line directly before it. |

The line itself does not have to be in canonical form. Verification recomputes canonical form from the parsed object.

## 3. Append rules

To append state `S` to a ledger whose last entry has ID `H`:

1. Compute `id = STATE_ID(S)`.
2. If `id == H`, **do not append**. The boundary has not changed.
3. Otherwise, write `S` with `state_id = id` and `previous_state_id = H` (or `null` if the ledger is empty) as a new final line.

Existing lines MUST NOT be modified, reordered or deleted.

A state ID MAY appear more than once in a ledger, for example when a boundary reverts A → B → A. That is a legitimate history, and each occurrence is a separate entry.

## 4. Offline verification procedure

Given a ledger file, a verifier MUST do the following, stopping at the first failure:

```
prev_id := null
target  := null
for each line n (1-based):
    obj := JSON-parse(line)                         # fail: malformed JSON
    validate obj against security-state-v1          # fail: schema violation
    require "state_id" in obj and "previous_state_id" in obj
    recomputed := SHA256_HEX(canonical_json(obj minus state_id, previous_state_id))
    require recomputed == obj.state_id              # fail: entry content altered
    require obj.previous_state_id == prev_id        # fail: chain broken / reordered / entry removed
    require obj.state_id != prev_id                 # fail: no-op append
    if n == 1: target := obj.target
    require obj.target == target                    # fail: mixed targets
    prev_id := obj.state_id
accept; ledger head := prev_id
```

The verifier SHOULD report the failing line number and which check failed.

## 5. What verification proves, and what it does not

**Proven** by a ledger that passes verification:

- Each entry's content matches its own STATE ID. No entry was edited after its ID was computed.
- The entries form one unbroken sequence. No entry was removed from the middle, inserted or reordered, *relative to the rest of the file as presented*.

**Not proven:**

- **Truncation.** Removing entries from the end still gives a valid ledger. Detecting truncation requires comparing against a head ID recorded elsewhere, such as a passport ([boundary-passport-v1](boundary-passport-v1.md)) or a published head.
- **Wholesale rewrite.** Because STATE IDs depend only on content, anyone can write a new, internally consistent ledger. Authenticity requires a signature over the ledger head, which v1 does not define.
- **Truth of the states.** The ledger shows consistency, not correctness. How strong the evidence was for each state is recorded in its observation.
