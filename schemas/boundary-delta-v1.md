# boundary-delta-v1

**Status:** Draft, normative
**Identifier:** `boundary-delta-v1`
**Depends on:** [security-state-v1](security-state-v1.md)
**Reference implementation:** `mcp_authscan/evidence/delta.py`

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary delta describes the transition between two security states of the **same target**, `prev → curr`. It is a pure function of the two states: the same inputs MUST give byte-identical canonical output. It does not use observations, timestamps or scanner metadata.

If the two `target` values differ, a producer MUST refuse to compute a delta.

## 2. Object structure

| Path | Type | Meaning |
|---|---|---|
| `schema` | string | `"boundary-delta-v1"` |
| `target` | string | The shared target. |
| `from_state_id` | string | STATE ID of `prev`. |
| `to_state_id` | string | STATE ID of `curr`. |
| `tool_visibility.unauthenticated_tools` | set-diff | §3.1 |
| `tool_visibility.authenticated_tools` | set-diff | §3.1 |
| `dimensions.audience` | dimension | §3.2 |
| `dimensions.cors` | dimension | §3.2 |
| `dimensions.origin` | dimension | §3.2 |
| `compensating_tightening` | list of string | Names of dimensions with `tightened: true`, sorted. |
| `classification` | string | §4 |
| `rule` | string | ID of the rule that produced `classification` (§4). |

### 3.1 Set-diff

```json
{"comparable": true, "added": ["…"], "removed": ["…"]}
```

- If both sides are lists: `comparable: true`. `added` = curr − prev and `removed` = prev − curr, each sorted by code point.
- If both sides are `null`: `comparable: false`, `added: []`, `removed: []`.
- If exactly one side is `null`: `comparable: false`, `added: null`, `removed: null`.

### 3.2 Dimension

```json
{"tightened": bool, "loosened": bool, "undetermined": bool, "changes": [ … ]}
```

`changes` has one entry per field whose value differs, sorted by `field`:

```json
{"field": "allow_credentials", "before": true, "after": false, "direction": "tightened"}
```

Each field's direction is determined as follows:

| Field | Tightened when | Loosened when |
|---|---|---|
| `audience.enforced` | `false → true` | `true → false` |
| `origin.validated` | `false → true` | `true → false` |
| `cors.allow_origin_wildcard` | `true → false` | `false → true` |
| `cors.allow_credentials` | `true → false` | `false → true` |
| `audience.accepted_audiences`, `origin.allowed_origins`, `cors.allowed_origins` (allowlists) | curr is a **proper subset** of prev | curr is a **proper superset** of prev |

Additional direction values:

- **mixed**: an allowlist both gained and lost entries.
- **undetermined**: exactly one of `before` and `after` is `null`.

Dimension flags:

- `loosened` = at least one change is `loosened` or `mixed`. A mixed change counts as loosening because it grants something that was not granted before.
- `tightened` = at least one change is `tightened` **and** `loosened` is false. A dimension that tightens one field and loosens another is not a compensating tightening.
- `undetermined` = at least one change is `undetermined`.

A change to or from `null` is never a tightening. Unknown values cannot compensate for anything.

## 4. Classification (normative)

The rules are evaluated in order. The first match wins.

| Rule | Condition | Classification |
|---|---|---|
| BD-R0 | `from_state_id == to_state_id` | `NO_CHANGE` |
| **BD-R1** | `unauthenticated_tools.comparable` and `added` is non-empty, **and** no dimension among audience, origin and CORS has `tightened: true` | **`AUTHORIZATION_REGRESSION`** |
| BD-R2 | `unauthenticated_tools.comparable` and `added` is non-empty, and at least one of those dimensions has `tightened: true` | `EXPOSURE_COMPENSATED` |
| BD-R3 | any dimension has `loosened: true` | `BOUNDARY_LOOSENED` |
| BD-R4 | `unauthenticated_tools.added` is `null` (exactly one side unknown), or any dimension has `undetermined: true` | `INDETERMINATE` |
| BD-R5 | any dimension has `tightened: true`, or `unauthenticated_tools.removed` is non-empty | `BOUNDARY_TIGHTENED` |
| BD-R6 | otherwise. For example, only `authenticated_tools` changed. | `CHANGED_NEUTRAL` |

### 4.1 The AUTHORIZATION_REGRESSION rule

> An increase in `tool_visibility.unauthenticated_tools` with no compensating tightening of audience, origin or CORS MUST produce the classification `AUTHORIZATION_REGRESSION`.

"Increase" means **the set gained at least one member** (`added` non-empty). The list does not have to get longer. A swap, where one tool stops being exposed without authentication and a different tool starts, is still an increase, because a tool that was not reachable without credentials now is.

"Compensating tightening" means a dimension with `tightened: true` as defined in §3.2.

`EXPOSURE_COMPENSATED` is not a pass. It records that exposure grew while some other control got stricter. Consumers SHOULD still surface it for human review.

## 5. Test vector

`prev` is the state in security-state-v1 §6 (STATE ID `bb047be1…0f5c`). `curr` is the same state with `tool_visibility.unauthenticated_tools = ["delete_doc", "list_docs"]`.

```json
{
  "schema": "boundary-delta-v1",
  "target": "https://mcp.example.com/mcp",
  "from_state_id": "bb047be12442528b0cdd570f9a83b0b57ef2518f07604d18a513891057ea0f5c",
  "to_state_id": "0cee097911779d8e92901ae80298bf39849d6a9def0fed02ece4a412954cc5c9",
  "tool_visibility": {
    "unauthenticated_tools": {"comparable": true, "added": ["delete_doc"], "removed": []},
    "authenticated_tools": {"comparable": true, "added": [], "removed": []}
  },
  "dimensions": {
    "audience": {"tightened": false, "loosened": false, "undetermined": false, "changes": []},
    "cors":     {"tightened": false, "loosened": false, "undetermined": false, "changes": []},
    "origin":   {"tightened": false, "loosened": false, "undetermined": false, "changes": []}
  },
  "compensating_tightening": [],
  "classification": "AUTHORIZATION_REGRESSION",
  "rule": "BD-R1"
}
```

If `curr` also sets `origin.allowed_origins = []` (a proper subset of `["https://app.example.com"]`), the result is `EXPOSURE_COMPENSATED` with `compensating_tightening: ["origin"]`.
