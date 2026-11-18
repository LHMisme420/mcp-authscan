# observation-v1

**Status:** Draft, normative
**Identifier:** `observation-v1`
**Depends on:** [security-state-v1](security-state-v1.md)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

An observation is the envelope that records **how** a security state was seen: when, by which scanner, and how much of the boundary the scan actually established. It wraps exactly one security state.

**The observation envelope is never included in the STATE ID.** No field defined here, and no other part of this object, feeds into the hash defined in security-state-v1 §5. Two observations that differ in timing, scanner version or coverage, but wrap identical states, refer to the same STATE ID. This split is intentional. The state says what the boundary *is*. The observation says how strong the evidence is.

## 2. Object structure

| Path | Type | Required | Meaning |
|---|---|---|---|
| `schema` | string | yes | MUST be exactly `"observation-v1"`. |
| `state_id` | string | yes | The STATE ID of `state`. It MUST equal the value recomputed from `state`. |
| `state` | object | yes | A valid security-state-v1 object. It MAY carry `state_id` / `previous_state_id`. If it does, `state.state_id` MUST equal the top-level `state_id`. |
| `observed_at` | object | yes | |
| `observed_at.start` | string | yes | RFC 3339 UTC timestamp with a `Z` suffix, when the scan began. |
| `observed_at.end` | string | yes | RFC 3339 UTC timestamp with a `Z` suffix, when the scan ended. MUST NOT be earlier than `start`. |
| `scanner` | object | yes | |
| `scanner.name` | string | yes | For example `"mcp-authscan"`. |
| `scanner.version` | string | yes | Scanner release version. |
| `scanner.probe_set_version` | string | yes | Version of the probe set that ran. |
| `coverage` | object | yes | Counts of probe verdicts (§3). |
| `coverage.in_scope` | integer ≥ 0 | yes | Probes that ran. |
| `coverage.pass` | integer ≥ 0 | yes | |
| `coverage.fail` | integer ≥ 0 | yes | |
| `coverage.not_observed` | integer ≥ 0 | yes | |
| `coverage.excluded` | integer ≥ 0 | yes | Probes that could not run. Not part of `in_scope`. |
| `not_observed` | list | yes | One entry per NOT_OBSERVED probe (§4). MAY be empty. |
| `excluded` | list | yes | One entry per EXCLUDED probe (§4). MAY be empty. |
| `unestablished` | list | no (SHOULD) | One entry per `null` field in `state`, giving the reason the field was not established (§4.1). |

Producers MAY add extra top-level keys. Consumers MUST ignore keys they do not recognize. This is safe because the observation is never hashed into a STATE ID.

## 3. Verdicts and coverage invariants

Each probe ends with exactly one verdict:

- **PASS**: the property was positively demonstrated.
- **FAIL**: the property was demonstrably absent.
- **NOT_OBSERVED**: the probe ran, but the response established neither PASS nor FAIL.
- **EXCLUDED**: the probe could not run because a named prerequisite was missing. It leaves the coverage denominator.

The following MUST hold:

```
coverage.in_scope       == coverage.pass + coverage.fail + coverage.not_observed
coverage.not_observed   == len(not_observed)
coverage.excluded       == len(excluded)
```

Conclusive coverage is `(pass + fail) / in_scope`. It is undefined when `in_scope == 0`. Consumers that display coverage MUST show it as conclusive coverage over in-scope probes, and MUST report EXCLUDED probes separately.

## 4. NOT_OBSERVED and EXCLUDED entries

Each entry in `not_observed`:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `probe_id` | string | yes | Stable probe identifier. |
| `reason` | string | yes | Why the probe was inconclusive, for example `"tools/list returned HTTP 502"`. |
| `affects` | list of string | yes | Dotted security-state paths whose value this probe would have established, for example `["cors.allow_credentials"]`. MAY be empty. |

Each entry in `excluded`:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `probe_id` | string | yes | |
| `missing_prerequisite` | string | yes | The prerequisite that was missing, for example `"no bearer token supplied"`. |
| `affects` | list of string | yes | As above. |

Consistency rule: if a field listed in any entry's `affects` was not established by some other probe, the wrapped state MUST carry `null` for that field. A producer MUST NOT fill a field with a guessed or default value when the probe for it did not conclude.

Both lists SHOULD be sorted by `probe_id`.

### 4.1 Unestablished fields

Some state fields are `null` because no probe in the run covers them at all, not because a probe was inconclusive. For example, the scanner may not have an Origin-validation probe, or may record a tool count but not tool names. Those fields would otherwise have no recorded reason. Each entry in `unestablished`:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `field` | string | yes | Dotted state path, for example `"tool_visibility.unauthenticated_tools"`. |
| `reason` | string | yes | Why the producer could not establish it. |

When present, `unestablished` MUST have exactly one entry for every `null` field in `state`, and no entries for non-null fields. It SHOULD be sorted by `field`.

## 5. Verification

A consumer verifying an observation MUST:

1. Validate `state` against security-state-v1. This includes the key, type and sort rules.
2. Recompute the STATE ID of `state` and compare it with `state_id`.
3. Check the coverage invariants in §3.
4. Check `observed_at.end >= observed_at.start`.
5. If `unestablished` is present, check that its `field` values are exactly the set of `null` fields in `state`.

If any check fails, the observation is invalid.
