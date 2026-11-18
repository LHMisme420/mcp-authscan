# boundary-passport-v1

**Status:** Draft, normative
**Identifier:** `boundary-passport-v1`
**Depends on:** [security-state-v1](security-state-v1.md), [observation-v1](observation-v1.md), [boundary-ledger-v1](boundary-ledger-v1.md)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary passport is a single portable JSON document that carries:

- the **current** security state of a target,
- the **current** observation of that state, and
- the **lineage**: the ordered chain of STATE ID pairs from genesis to the current state.

A recipient can check it offline without the full ledger. If the recipient also has the ledger, it can check that the passport matches it.

## 2. Object structure

| Path | Type | Required | Meaning |
|---|---|---|---|
| `schema` | string | yes | `"boundary-passport-v1"` |
| `target` | string | yes | MUST equal `current_state.target`. |
| `current_state` | object | yes | A security-state-v1 object that MUST carry `state_id` and `previous_state_id`. This is the ledger head. |
| `current_observation` | object | yes | An observation-v1 object whose `state_id` equals `current_state.state_id`. |
| `lineage` | list of pairs | yes | §3 |
| `issued_at` | string | yes | RFC 3339 UTC timestamp with a `Z` suffix, when the passport was assembled. |

Like the observation, the passport is never part of any STATE ID.

## 3. Lineage

`lineage` lists `[previous_state_id, state_id]` pairs, **oldest first**, one per ledger entry:

```json
"lineage": [
  [null, "bb047be12442528b0cdd570f9a83b0b57ef2518f07604d18a513891057ea0f5c"],
  ["bb047be12442528b0cdd570f9a83b0b57ef2518f07604d18a513891057ea0f5c", "0cee097911779d8e92901ae80298bf39849d6a9def0fed02ece4a412954cc5c9"]
]
```

Rules:

1. `lineage[0][0]` MUST be `null`. Lineage always starts at genesis, and v1 has no truncated lineage.
2. For every `i > 0`: `lineage[i][0] == lineage[i-1][1]`.
3. For every `i`: `lineage[i][0] != lineage[i][1]`.
4. The last pair MUST equal `[current_state.previous_state_id, current_state.state_id]`.
5. Every ID is either `null` (first position of the first pair only) or 64 lowercase hex characters.

## 4. Verification

### 4.1 Standalone (passport only)

1. Check `schema`, and check that `target == current_state.target`.
2. Validate `current_state` against security-state-v1. Recompute its STATE ID and require it to equal `current_state.state_id`.
3. Verify `current_observation` per observation-v1 §5, and require `current_observation.state_id == current_state.state_id`.
4. Check lineage rules 1–5 in §3.

### 4.2 Against a ledger

5. Verify the ledger per boundary-ledger-v1 §4.
6. Require the ledger to have exactly `len(lineage)` entries, with entry `i` having `[previous_state_id, state_id] == lineage[i]`.
7. Require the last ledger entry's `state_id` to equal `current_state.state_id`.

## 5. What a passport proves, and what it does not

**Proven standalone:** the current state's content matches its ID. The observation refers to that exact state. The lineage is an internally consistent chain that ends at that state.

**Not proven standalone:** the *content* of earlier states. The lineage carries only their IDs. To inspect an earlier boundary, the recipient needs the ledger entry whose content hashes to that ID.

**Not proven at all in v1:** who issued the passport. Anyone can build a consistent passport. Binding a passport to an issuer requires a signature, which v1 deliberately does not define. A future version will add a detached signature over the canonical passport.
