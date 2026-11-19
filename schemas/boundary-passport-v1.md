# boundary-passport-v1

**Status:** Draft, normative
**Depends on:** [security-state-v1](security-state-v1.md), [observation-v1](observation-v1.md), [boundary-ledger-v1](boundary-ledger-v1.md)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary passport is a single portable JSON document for **one target at one access class**. It carries:

- the **current** security state (the ledger head),
- the **current** observation of that state, which also binds the target, and
- the **lineage**: the ordered chain of STATE ID pairs from genesis to the current state.

A recipient can verify it offline. With the ledger as well, the recipient can verify it against the full history.

## 2. Object structure

| Key | Type | Required | Meaning |
|---|---|---|---|
| `schema` | string | yes | `"boundary-passport-v1"` |
| `target` | string | yes | MUST equal `current_observation.target`. |
| `access_class` | string | yes | MUST equal `current_state.access_class`. |
| `current_state` | object | yes | A security-state-v1 object carrying `state_id` and `previous_state_id`. |
| `current_observation` | object | yes | An observation-v1 object with `state_id == current_state.state_id`. |
| `lineage` | list of pairs | yes | §3 |
| `issued_at` | string | yes | RFC 3339 UTC timestamp with a `Z` suffix. |

The passport is never part of any STATE ID.

## 3. Lineage

`[previous_state_id, state_id]` pairs, **oldest first**, one per ledger entry:

```json
"lineage": [
  [null, "b1208b5f7f7bc9efc82553a985da05d9a241a5d1e3cd3fbd858968c9bf0ec477"],
  ["b1208b5f7f7bc9efc82553a985da05d9a241a5d1e3cd3fbd858968c9bf0ec477", "bae770a9a7658457c094cd8e8e9fc333d7155182e4a393ca2ff31f9f00061c27"]
]
```

1. `lineage[0][0]` MUST be `null`. v1 has no truncated lineage.
2. For every `i > 0`: `lineage[i][0] == lineage[i-1][1]`.
3. For every `i`: `lineage[i][0] != lineage[i][1]`.
4. The last pair MUST equal `[current_state.previous_state_id, current_state.state_id]`.
5. Every ID is 64 lowercase hex characters. The one exception is the `null` in position 0 of the first pair.

## 4. Verification

### 4.1 Standalone

1. Check `schema`, `target == current_observation.target`, and `access_class == current_state.access_class`.
2. Validate `current_state` against security-state-v1, including the `state_id` match.
3. Verify `current_observation` per observation-v1 §5, and require `current_observation.state_id == current_state.state_id`.
4. Check lineage rules 1–5.

### 4.2 Against a ledger

5. Verify the ledger per boundary-ledger-v1 §4, and check that its header has `target == target` and `access_class == access_class`.
6. The ledger MUST have exactly `len(lineage)` entries after the header, with entry `i` having `[previous_state_id, state_id] == lineage[i]`.
7. The last ledger entry's `state_id` MUST equal `current_state.state_id`.

## 5. What a passport proves, and what it does not

**Proven standalone:**

- The current state's content matches its ID.
- The observation refers to that exact state and names the target.
- The lineage is an internally consistent chain ending at that state.

**Not proven standalone:** the *content* of earlier states. The lineage carries only their IDs. Checking those needs the ledger.

**Not proven in v1:** who issued the passport, or that the target named in the observation is the one actually captured. Both need a signature, which v1 does not define.
