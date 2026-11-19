# boundary-ledger-v1

**Status:** Draft, normative
**Depends on:** [security-state-v1](security-state-v1.md)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary ledger is the append-only history of distinct security states for **one target at one access class**. Each entry links to the one before it by STATE ID. It can be verified offline with nothing but SHA-256 and the canonical JSON rules in security-state-v1 §5.

A target with both anonymous and authenticated captures has **two ledgers**, one per access class. A delta never compares across classes, so their histories never mix.

States carry no target. Which target a ledger belongs to is recorded outside the states: in its file name, for example `<host>/<access_class>.jsonl`, and in the observations and passports that reference it.

The ledger records **boundary changes**, not scans. A capture whose state matches the ledger head adds no entry. Its evidence goes in an [observation-v1](observation-v1.md) instead.

## 2. Format

JSON Lines: one JSON object per line, separated by `\n`, with no blank lines. The extension SHOULD be `.jsonl`.

Each line is a security-state-v1 object that MUST carry both chaining keys:

| Key | Value |
|---|---|
| `state_id` | This entry's STATE ID. Chaining keys are excluded when computing it. |
| `previous_state_id` | `null` for the first entry. Otherwise, the `state_id` of the line directly before. |

## 3. Append rules

To append state `S` to a ledger whose head has ID `H`:

1. `S.access_class` MUST equal the ledger's access class (that of line 1).
2. Compute `id = STATE_ID(S)`. If `id == H`, **do not append**.
3. Otherwise, write `S` with `state_id = id` and `previous_state_id = H` (or `null` if the ledger is empty) as a new final line.

Lines MUST NOT be modified, reordered or deleted. A STATE ID MAY occur more than once, for example A → B → A.

## 4. Offline verification procedure

```
prev_id := null
klass   := null
for each line n (1-based):
    obj := JSON-parse(line)                            # fail: malformed JSON
    validate obj against security-state-v1             # fail: schema violation
    require "state_id" in obj and "previous_state_id" in obj
    recomputed := SHA256_HEX(canonical_json(obj minus state_id, previous_state_id))
    require recomputed == obj.state_id                 # fail: entry content altered
    require obj.previous_state_id == prev_id           # fail: chain broken / reordered / entry removed
    require obj.state_id != prev_id                    # fail: no-op append
    if n == 1: klass := obj.access_class
    require obj.access_class == klass                  # fail: mixed access classes
    prev_id := obj.state_id
accept; ledger head := prev_id
```

The verifier SHOULD report the failing line number and which check failed.

## 5. What verification proves, and what it does not

**Proven:**

- Each entry's content matches its own STATE ID.
- The entries form one unbroken sequence at one access class. No entry was removed from the middle, inserted or reordered, *relative to the file as presented*.

**Not proven:**

- **Truncation.** Cutting entries off the end still leaves a valid ledger. Detect it by comparing against a head ID recorded elsewhere, such as a passport.
- **Wholesale rewrite.** STATE IDs depend only on content, so anyone can produce a consistent ledger. Authenticity needs a signature, which v1 does not define.
- **Which target.** Target binding lives outside the ledger (see §1).
- **Cross-class exposure.** The two ledgers of one target are never compared with each other, so a server opening anonymous access for the first time leaves no delta. See boundary-delta-v1 §5.
- **Truth.** The ledger shows consistency, not correctness. The evidence for each state is in its observation.
