# observation-v1

**Status:** Draft, normative
**Depends on:** [security-state-v1](security-state-v1.md)
**Reference implementation:** `mcp_authscan/evidence/observation.py` (`verify_observation`)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

An observation is the envelope that records **where, when and how** a security state was seen: which target, when, by which scanner, and how much the run actually established. It wraps exactly one security state.

**The observation envelope is never included in the STATE ID.** Two observations that differ in target, timing, scanner version or coverage, but wrap identical states, refer to the same STATE ID. The state records what is exposed at an access class. The observation records where it was seen and how strong the evidence is.

## 2. Object structure

| Key | Type | Required | Meaning |
|---|---|---|---|
| `schema` | string | yes | MUST be exactly `"observation-v1"`. |
| `target` | string | yes | URL of the MCP endpoint, normalized as in §2.1. |
| `state_id` | string | yes | The STATE ID of `state`. MUST equal the value recomputed from `state`. |
| `state` | object | yes | A valid security-state-v1 object. It MAY carry `state_id` / `previous_state_id`. If it does, `state.state_id` MUST equal the top-level `state_id`. |
| `observed_at.start` | string | yes | RFC 3339 UTC timestamp with a `Z` suffix, when capture began. |
| `observed_at.end` | string | yes | RFC 3339 UTC timestamp with a `Z` suffix, when capture ended. MUST NOT be earlier than `start`. |
| `scanner.name` | string | yes | For example `"mcp-authscan"`. |
| `scanner.version` | string | yes | |
| `scanner.probe_set_version` | string | yes | |
| `coverage` | object | yes | §3 |
| `not_observed` | list | yes | One entry per NOT_OBSERVED probe (§4). MAY be empty. |
| `excluded` | list | yes | One entry per EXCLUDED probe (§4). MAY be empty. |
| `capture` | object | no (SHOULD) | How the surface capture went (§4.1). |

Producers MAY add extra top-level keys, and consumers MUST ignore keys they do not recognize. This is safe because the observation is never hashed.

### 2.1 Target normalization

- Scheme and host in lowercase.
- Default port removed (`:443` for https, `:80` for http).
- Path kept as given.
- No query string, fragment or userinfo.

## 3. Verdicts and coverage invariants

Each probe ends with exactly one verdict:

- **PASS**: the property was positively demonstrated.
- **FAIL**: the property was demonstrably absent.
- **NOT_OBSERVED**: the probe ran, but the response established neither PASS nor FAIL.
- **EXCLUDED**: the probe could not run because a named prerequisite was missing. It is not counted in `in_scope`.

| Key | Type |
|---|---|
| `coverage.in_scope` | integer ≥ 0 |
| `coverage.pass` | integer ≥ 0 |
| `coverage.fail` | integer ≥ 0 |
| `coverage.not_observed` | integer ≥ 0 |
| `coverage.excluded` | integer ≥ 0 |

The following MUST hold:

```
coverage.in_scope     == coverage.pass + coverage.fail + coverage.not_observed
coverage.not_observed == len(not_observed)
coverage.excluded     == len(excluded)
```

Conclusive coverage is `(pass + fail) / in_scope`. It is undefined when `in_scope == 0`.

## 4. NOT_OBSERVED and EXCLUDED entries

`not_observed[]` entries:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `probe_id` | string | yes | A probe identifier that is unique within the run. |
| `reason` | string | yes | Why the probe was inconclusive. |
| `affects` | list of string | no | State keys this probe bears on, for example `["tools"]`. |

`excluded[]` entries:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `probe_id` | string | yes | |
| `missing_prerequisite` | string | yes | |
| `affects` | list of string | no | As above. |

Both lists SHOULD be sorted by `probe_id`.

A security state has no "unknown" values. A producer that could not complete `initialize`, `tools/list`, `prompts/list` and `resources/list` at an access class MUST NOT emit a state for that class. The one exception is §4.1.

### 4.1 `capture` and the refused anonymous capture

`capture` is `{"status": "complete" | "refused", "reasons": [string, ...]}`.

- `complete`: every call was answered. `reasons` MAY be empty.
- `refused`: the **anonymous** capture ran and `initialize` was answered with HTTP 401 or 403. The producer MUST then emit the **empty anonymous state**: no tools, prompts or resources, and empty instructions. Its STATE ID is `f91b3009b031cd660ff79f978b7b6c5ac0b85530ff93e55b2c173f9cdd743f52`. `reasons` MUST be non-empty and MUST record the refusal.

The refusal is recorded **here, never in the state**. A server that was not reached, answered with any other error, or failed part of the capture gets no state at all. A refused credential at the authenticated class also gets no state.

## 5. Verification

A consumer MUST:

1. Check that `target` is normalized as in §2.1.
2. Validate `state` against security-state-v1. This includes key, type, sort and `state_id` checks.
3. Recompute the STATE ID of `state` and compare it with `state_id`.
4. Check `observed_at` (format and `end >= start`), `scanner`, and the coverage invariants in §3.
5. If `capture` is present, check its shape. If `capture.status` is `refused`, require the wrapped state to be the empty anonymous state and `reasons` to be non-empty.

If any check fails, the observation is invalid.
