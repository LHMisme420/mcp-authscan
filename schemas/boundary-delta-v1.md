# boundary-delta-v1

**Status:** Draft, normative
**Depends on:** [security-state-v1](security-state-v1.md), [observation-v1](observation-v1.md)
**Reference implementation:** `mcp_authscan/evidence/delta.py`

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary delta describes the transition `prev → curr` between two security states of **one target**.

The inputs are two **observations** ([observation-v1](observation-v1.md)), not bare states. The observation carries the target, and the state deliberately does not. Taking observations lets the delta refuse a cross-target pair as part of the computation itself, rather than relying on callers to pair states correctly. The state stays a pure boundary.

The output depends only on the two wrapped states and the shared target. Timestamps are used only for the ordering check (§2.1). Scanner metadata and coverage are not used.

## 2. Refusals (normative)

Before classifying anything, a producer MUST check the following, and MUST refuse by raising an error rather than producing a delta object:

1. **Invalid input.** Either observation fails observation-v1 §5 verification.
2. **Different targets.** `prev.target != curr.target`.
3. **Wrong order.** `curr.observed_at.start < prev.observed_at.start`. Reversing the order would turn a regression into a reduction, so the direction is checked, not assumed.

A refusal is not a classification. No delta object exists for a refused pair.

### 2.1 Different access classes are not a refusal

Two observations of the same target at different access classes produce a delta with classification `ACCESS_CLASS_CHANGED` and no comparison of their contents (§4, BD-R1). It is a valid statement of fact about the two inputs: they describe different boundaries.

## 3. Object structure

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | `"boundary-delta-v1"` |
| `target` | string | The shared target. |
| `access_class` | object | `{"from": prev.state.access_class, "to": curr.state.access_class}` |
| `from_state_id` | string | STATE ID of `prev.state`. |
| `to_state_id` | string | STATE ID of `curr.state`. |
| `tools` | set-diff or null | |
| `prompts` | set-diff or null | |
| `resources` | set-diff or null | |
| `surface_digest_changed` | boolean or null | |
| `instructions_changed` | boolean or null | |
| `classification` | string | §4 |
| `rule` | string | The rule that produced `classification`. |

A set-diff is `{"added": [...], "removed": [...]}`, computed as set difference and sorted by code point.

When the access classes differ, every diff and flag field MUST be `null`.

## 4. Classification (normative)

The rules are evaluated in order, after the refusals in §2. The first match wins.

| Rule | Condition | Classification |
|---|---|---|
| BD-R1 | access classes differ | `ACCESS_CLASS_CHANGED` |
| BD-R0 | `from_state_id == to_state_id` | `NO_CHANGE` |
| **BD-R2** | class is `anonymous` and `tools.added` is non-empty | **`AUTHORIZATION_REGRESSION`** |
| BD-R3 | any `added` list is non-empty | `SURFACE_EXPANDED` |
| BD-R4 | any `removed` list is non-empty | `SURFACE_REDUCED` |
| BD-R5 | otherwise: the name sets are equal but a digest differs | `DEFINITIONS_CHANGED` |

The flags and set-diffs always carry the full picture. `classification` names only the highest-priority rule that matched.

### 4.1 The AUTHORIZATION_REGRESSION rule

> At the anonymous access class, a tool name that appears in `curr` and not in `prev` MUST produce `AUTHORIZATION_REGRESSION`.

- **Set membership, not count.** A swap, where one tool goes and another appears, is still a regression.
- **Anonymous class only.** A new tool at the authenticated class is `SURFACE_EXPANDED`. Adding tools behind authentication is ordinary development, and treating it as a regression would make the label meaningless.
- **Nothing compensates.** v1 states carry no authorization controls, so no other change can offset new anonymous exposure.
- **Prompts and resources** added at the anonymous class are `SURFACE_EXPANDED`. Consumers SHOULD still surface new anonymous resources for review.

## 5. Known limits

- **The anonymous and authenticated views are never compared with each other.** Each class is compared only with itself (BD-R1), and each class has its own ledger. The most serious regression, a tool that used to require a token and now appears anonymously, is caught in v1 only in part:
  - **Caught:** the anonymous ledger already has a state, and the tool's name is new to it. BD-R2 fires.
  - **Not caught: a closed server opening up.** If the server previously refused anonymous access entirely, there is no earlier anonymous state (observation-v1 §4: no state is emitted for a class whose lists could not be captured). The first anonymous state becomes a ledger genesis, and no delta is ever computed. A server going from fully gated to fully open produces no regression.
  - **Not caught: why a tool is new.** BD-R2 cannot tell a brand-new tool apart from one that *crossed* from authenticated to anonymous. Both are reported identically, although a crossing is the more serious finding.

  Closing both gaps needs **one paired read across both classes of the same target at the same time**, which compares anonymous names against authenticated names directly. **Planned for v2, not specified in v1.**
- **Authenticity.** A delta is only as trustworthy as its input observations. v1 does not sign them.

## 6. Test vectors

Both observations are of target `https://mcp.example.com/mcp`, with `prev` observed before `curr`. Every other observation field is irrelevant to the output.

`prev.state` is the anonymous state from security-state-v1 §6 (STATE ID `b1208b5f…c477`). `curr.state` is built from the same surface plus `{"name": "delete_doc", "description": "Delete a document", "inputSchema": {"type": "object"}}` at the anonymous class:

```json
{
  "schema": "boundary-delta-v1",
  "target": "https://mcp.example.com/mcp",
  "access_class": {"from": "anonymous", "to": "anonymous"},
  "from_state_id": "b1208b5f7f7bc9efc82553a985da05d9a241a5d1e3cd3fbd858968c9bf0ec477",
  "to_state_id": "bae770a9a7658457c094cd8e8e9fc333d7155182e4a393ca2ff31f9f00061c27",
  "tools": {"added": ["delete_doc"], "removed": []},
  "prompts": {"added": [], "removed": []},
  "resources": {"added": [], "removed": []},
  "surface_digest_changed": true,
  "instructions_changed": false,
  "classification": "AUTHORIZATION_REGRESSION",
  "rule": "BD-R2"
}
```

The same pair at the authenticated class gives `SURFACE_EXPANDED` (BD-R3).

The anonymous `prev` against the authenticated state from security-state-v1 §6 gives:

```json
{
  "schema": "boundary-delta-v1",
  "target": "https://mcp.example.com/mcp",
  "access_class": {"from": "anonymous", "to": "authenticated"},
  "from_state_id": "b1208b5f7f7bc9efc82553a985da05d9a241a5d1e3cd3fbd858968c9bf0ec477",
  "to_state_id": "4ea87f47989d6299671564d77b9c7be2788e46b564546216315af5ea1fbeb184",
  "tools": null,
  "prompts": null,
  "resources": null,
  "surface_digest_changed": null,
  "instructions_changed": null,
  "classification": "ACCESS_CLASS_CHANGED",
  "rule": "BD-R1"
}
```

If `curr.target` is `https://other.example.com/mcp` instead, no delta is produced. The pair is refused under §2.
