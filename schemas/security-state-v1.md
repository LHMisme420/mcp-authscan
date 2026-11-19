# security-state-v1

**Status:** Draft, normative
**Reference implementation:** `mcp_authscan/evidence/state.py` (with `mcp_authscan/surface.py` for the canonical form and `surface_digest`). This spec does not depend on either file.

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A security state records **what one MCP server exposes at one access class**: the names of the tools, prompts and resources it lists, plus digests of their full definitions and of its instructions.

A server has two separate boundaries: what an anonymous client sees and what an authenticated client sees. The access class is therefore part of the state itself, not a note about how the state was collected. It is hashed into the STATE ID, so two states captured at different access classes **never** share an ID.

A state contains no timestamps, no target and no coverage. Those belong to the observation envelope ([observation-v1](observation-v1.md)). Two captures of the same surface at the same access class MUST produce the same STATE ID, whenever and wherever they ran.

## 2. Object structure

Every content key is **required**. No other content keys are permitted.

| Key | Type | Meaning |
|---|---|---|
| `state_version` | string | MUST be exactly `"1"`. |
| `access_class` | string | `"anonymous"` (captured with no credential) or `"authenticated"` (captured with a credential). |
| `surface_digest` | string | 64 lowercase hex characters. SHA-256 of the canonical surface (§4). Covers the full definitions, not just the names. |
| `tools` | list of string | The `name` of every tool in `tools/list`, sorted (§3). |
| `prompts` | list of string | The `name` of every prompt in `prompts/list`, sorted. |
| `resources` | list of string | The `uri` of every resource in `resources/list`, sorted. |
| `instructions_digest` | string | 64 lowercase hex characters. SHA-256 of the UTF-8 bytes of the `instructions` string from `initialize`, or of the empty string if none was given. |

Two chaining keys MAY be present. They are **never** part of the STATE ID:

| Key | Type | Meaning |
|---|---|---|
| `state_id` | string or null | This state's STATE ID (§5). If present and non-null, it MUST equal the recomputed value. |
| `previous_state_id` | string or null | The STATE ID of the preceding ledger entry ([boundary-ledger-v1](boundary-ledger-v1.md)). |

A consumer MUST reject a state that has an unknown key, a missing content key, a wrong `state_version` or `access_class`, a malformed digest, an unsorted list, or a `state_id` that does not match its content. The error SHOULD name the offending key. A consumer MUST NOT silently re-sort or repair a state: rejecting it is what lets the STATE ID work as an integrity check.

## 3. Identifier lists

Each list holds the identifier field (`name` for tools and prompts, `uri` for resources) of every listed item that is a JSON object whose identifier is a string.

- Items that are not objects, or whose identifier is not a string, are left out of the list. They are still covered by `surface_digest`.
- Duplicates are kept. A server that lists a name twice has a list with that name twice.
- Lists are sorted in ascending **Unicode code point** order. This is not UTF-16 code-unit order and not locale collation. JavaScript implementers MUST compare by code point explicitly.

## 4. Canonical surface and `surface_digest`

The canonical surface is a JSON object with exactly four keys:

- `instructions`: the instructions string, or `""` if absent.
- `tools`: one row per tool. A row is the tool object reduced to whichever of `name`, `description`, `inputSchema` and `annotations` are present. Rows are sorted by `name`, with a missing name treated as `""`.
- `prompts`: one row per prompt object. A row is the prompt reduced to whichever of `name`, `description` and `arguments` are present. Rows are sorted by `name`. Items that are not objects are skipped.
- `resources`: one row per resource object. A row is the resource reduced to whichever of `uri`, `name`, `description` and `mimeType` are present. Rows are sorted by `uri`. Items that are not objects are skipped.

The sort is stable, so rows with equal sort keys keep their input order. `tools` items MUST be JSON objects.

`surface_digest` = SHA-256, as lowercase hex, of the UTF-8 bytes of the canonical surface serialized as canonical JSON (§5.2).

## 5. STATE ID

### 5.1 Rule

STATE ID = SHA-256, as 64 lowercase hex characters, of the UTF-8 bytes of the canonical JSON of the state **with `state_id` and `previous_state_id` removed**. Nothing else is removed.

### 5.2 Canonical JSON

- Object keys sorted ascending at every nesting level.
- No insignificant whitespace. The separators are exactly `,` and `:`.
- ASCII-only output (`ensure_ascii=True`). Characters above U+007F are written as `\uXXXX` with lowercase hex. Characters above U+FFFF are written as a UTF-16 surrogate pair (`😀`).
- Below U+0020: `\b \f \n \r \t`, or `\u00XX` otherwise. `"` becomes `\"` and `\` becomes `\\`. `/` is **not** escaped.

This is Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`. A security state contains only strings and lists of strings, so number formatting never arises.

## 6. Test vectors

Input surface:

```json
{
  "instructions": "Use list_docs before write_doc.",
  "tools": [
    {"name": "write_doc", "description": "Write a document", "inputSchema": {"type": "object"}},
    {"name": "list_docs", "description": "List documents", "inputSchema": {"type": "object"}}
  ],
  "prompts": [{"name": "summarize", "description": "Summarize a doc"}],
  "resources": [{"uri": "file:///docs/b.md", "name": "b"}, {"uri": "file:///docs/a.md", "name": "a"}]
}
```

Canonical surface:

```
{"instructions":"Use list_docs before write_doc.","prompts":[{"description":"Summarize a doc","name":"summarize"}],"resources":[{"name":"a","uri":"file:///docs/a.md"},{"name":"b","uri":"file:///docs/b.md"}],"tools":[{"description":"List documents","inputSchema":{"type":"object"},"name":"list_docs"},{"description":"Write a document","inputSchema":{"type":"object"},"name":"write_doc"}]}
```

Anonymous-class state:

```json
{
  "state_version": "1",
  "access_class": "anonymous",
  "surface_digest": "97b21b2bd8b9057e5e6196bad5bac627dfab07ae9ab780f5a570d17429c2a186",
  "tools": ["list_docs", "write_doc"],
  "prompts": ["summarize"],
  "resources": ["file:///docs/a.md", "file:///docs/b.md"],
  "instructions_digest": "09dc366d4fe480877cf5660c3c51300f9927e11ab16cda93bbbbd6c651c6ee61"
}
```

Canonical preimage:

```
{"access_class":"anonymous","instructions_digest":"09dc366d4fe480877cf5660c3c51300f9927e11ab16cda93bbbbd6c651c6ee61","prompts":["summarize"],"resources":["file:///docs/a.md","file:///docs/b.md"],"state_version":"1","surface_digest":"97b21b2bd8b9057e5e6196bad5bac627dfab07ae9ab780f5a570d17429c2a186","tools":["list_docs","write_doc"]}
```

STATE ID:

```
b1208b5f7f7bc9efc82553a985da05d9a241a5d1e3cd3fbd858968c9bf0ec477
```

The same surface with `"access_class": "authenticated"` has STATE ID:

```
4ea87f47989d6299671564d77b9c7be2788e46b564546216315af5ea1fbeb184
```

Escaping: `{"b":"é \n/","a":"😀"}` canonicalizes to `{"a":"😀","b":"é \n/"}`.

## 7. Out of scope

- **Target, timestamps, scanner identity and coverage.** These are in [observation-v1](observation-v1.md).
- **Authorization controls such as audience binding, Origin validation and CORS.** v1 records what is exposed at each access class, not how access is enforced.
- **Authenticity.** A STATE ID shows that a state's content was not changed after its ID was computed. It does not show who produced the state. Proving that needs a signature, which v1 does not define.
