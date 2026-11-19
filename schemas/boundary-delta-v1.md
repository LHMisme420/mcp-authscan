# boundary-delta-v1

**Status:** Draft, normative
**Depends on:** [security-state-v1](security-state-v1.md)
**Reference implementation:** `mcp_authscan/evidence/delta.py`

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A boundary delta describes the transition `prev → curr` between two security states. It is a pure function of the two states: the same inputs MUST produce byte-identical canonical output. It does not use observations, timestamps or scanner metadata.

A state describes one access class, so **states of different access classes are never compared.** Their delta records only that the class changed (§3, BD-R1).

A state carries no target. The caller is responsible for passing states of the same server, which is normally done by taking both from one ledger.

## 2. Object structure

| Key | Type | Meaning |
|---|---|---|
| `schema` | string | `"boundary-delta-v1"` |
| `access_class` | object | `{"from": prev.access_class, "to": curr.access_class}` |
| `from_state_id` | string | STATE ID of `prev`. |
| `to_state_id` | string | STATE ID of `curr`. |
| `tools` | set-diff or null | |
| `prompts` | set-diff or null | |
| `resources` | set-diff or null | |
| `surface_digest_changed` | boolean or null | `prev.surface_digest != curr.surface_digest` |
| `instructions_changed` | boolean or null | `prev.instructions_digest != curr.instructions_digest` |
| `classification` | string | §3 |
| `rule` | string | The rule that produced `classification`. |

A set-diff is `{"added": [...], "removed": [...]}`, where `added` = curr − prev and `removed` = prev − curr as sets, each sorted by code point. Duplicates within one list do not count as additions.

When the access classes differ, `tools`, `prompts`, `resources`, `surface_digest_changed` and `instructions_changed` MUST all be `null`.

## 3. Classification (normative)

The rules are evaluated in order. The first match wins.

| Rule | Condition | Classification |
|---|---|---|
| BD-R1 | `prev.access_class != curr.access_class` | `ACCESS_CLASS_CHANGED` |
| BD-R0 | `from_state_id == to_state_id` | `NO_CHANGE` |
| **BD-R2** | access class is `anonymous` and `tools.added` is non-empty | **`AUTHORIZATION_REGRESSION`** |
| BD-R3 | any of `tools.added`, `prompts.added`, `resources.added` is non-empty | `SURFACE_EXPANDED` |
| BD-R4 | any of the `removed` lists is non-empty | `SURFACE_REDUCED` |
| BD-R5 | otherwise: the name sets are equal, but `surface_digest` or `instructions_digest` differs | `DEFINITIONS_CHANGED` |

BD-R1 is checked before BD-R0, so a cross-class pair is never compared. Because the access class is hashed, two states of different classes never have equal IDs anyway.

The flags and set-diffs always carry the full picture. A transition can add a tool and change a description at the same time. `classification` names only the highest-priority rule that matched.

### 3.1 The AUTHORIZATION_REGRESSION rule

> At the anonymous access class, a tool name that appears in `curr` and not in `prev` MUST produce `AUTHORIZATION_REGRESSION`.

- **"Appears" means set membership, not count.** A swap, where one anonymous tool disappears and a different one appears, is still a regression, because a tool that needed credentials before (or did not exist) is now reachable without them.
- **Only the anonymous class.** A new tool at the authenticated class is `SURFACE_EXPANDED`. Adding tools behind authentication is ordinary development, and classifying it as a regression would make the label mean nothing.
- **Nothing compensates.** v1 states carry no authorization controls, so no other change can offset new anonymous exposure.
- **Prompts and resources** added at the anonymous class are `SURFACE_EXPANDED`, not `AUTHORIZATION_REGRESSION`. Consumers SHOULD still surface new anonymous resources for review, because resources can expose data.

`ACCESS_CLASS_CHANGED` is not a regression. It records that the two states describe different boundaries.

## 4. Test vectors

`prev` is the anonymous state in security-state-v1 §6 (STATE ID `b1208b5f…c477`). `curr` is the state built from the same surface with one more tool, `{"name": "delete_doc", "description": "Delete a document", "inputSchema": {"type": "object"}}`, at the anonymous class:

```json
{
  "schema": "boundary-delta-v1",
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
