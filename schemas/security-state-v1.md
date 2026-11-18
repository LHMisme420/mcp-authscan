# security-state-v1

**Status:** Draft, normative
**Identifier:** `security-state-v1`
**Reference implementation:** `mcp_authscan/evidence/state.py` (you don't need it to implement this spec)

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Purpose

A security state describes the **intrinsic authorization boundary** of one MCP endpoint: what the endpoint exposes, and to whom. It holds only facts about the target. It holds no facts about the scan that observed them (when the scan ran, which tool ran it, how many probes it ran). Those go in the observation envelope ([observation-v1](observation-v1.md)).

Two scans that see the same boundary MUST produce byte-identical canonical JSON, and so the same STATE ID, even if they ran at different times or with different scanner versions.

## 2. Object structure

A security state is a JSON object. Every field below is **required**. A field marked *nullable* MUST be present. It is set to `null` when the producer could not establish its value. `null` means "not determined". It never means "false" or "empty".

| Path | Type | Nullable | Meaning |
|---|---|---|---|
| `schema` | string | no | MUST be exactly `"security-state-v1"`. |
| `target` | string | no | Normalized URL of the MCP endpoint (§3). |
| `tool_visibility` | object | no | |
| `tool_visibility.unauthenticated_tools` | list of string | yes | Tool names returned by `tools/list` with no credentials. `[]` means the call succeeded or was refused and no tools were visible. `null` means it was not determined. |
| `tool_visibility.authenticated_tools` | list of string | yes | Tool names returned by `tools/list` with valid credentials. `null` when no credentials were available. |
| `audience` | object | no | Token audience binding. |
| `audience.enforced` | boolean | yes | `true` if the endpoint rejects tokens whose audience is not this resource. |
| `audience.accepted_audiences` | list of string | yes | Audience values the endpoint was shown to accept. |
| `origin` | object | no | `Origin` request-header validation. |
| `origin.validated` | boolean | yes | `true` if the endpoint rejects requests that carry a disallowed `Origin`. |
| `origin.allowed_origins` | list of string | yes | Origins the endpoint was shown to accept. |
| `cors` | object | no | CORS response policy. |
| `cors.allow_origin_wildcard` | boolean | yes | `true` if `Access-Control-Allow-Origin` is `*` **or** the endpoint reflects any supplied origin. A server that reflects origins is a wildcard for this purpose. |
| `cors.allow_credentials` | boolean | yes | `true` if `Access-Control-Allow-Credentials: true` is returned. |
| `cors.allowed_origins` | list of string | yes | Specific origins granted by CORS. |

Two keys MAY also appear at the top level. They are reserved for chaining ([boundary-ledger-v1](boundary-ledger-v1.md)):

| Path | Type | Meaning |
|---|---|---|
| `state_id` | string or null | This state's STATE ID (§5). |
| `previous_state_id` | string or null | The STATE ID of the preceding ledger entry. |

If present, each MUST be either `null` or 64 lowercase hexadecimal characters.

**No other keys are permitted** at the top level or inside any section. A consumer MUST reject a state with unknown keys. This keeps the STATE ID stable: v1 cannot be extended silently. Any new field needs a new schema version.

## 3. Target normalization

Producers MUST normalize `target` before emitting it:

- Scheme and host in lowercase.
- Default port removed (`:443` for `https`, `:80` for `http`).
- Path kept as given, with no trailing-slash rewriting.
- No query string, no fragment, no userinfo.

Two states that differ only in `target` describe different endpoints and have different STATE IDs.

## 4. List rules

Every list-valued field (all `*_tools`, `*_audiences` and `*_origins` lists) MUST:

1. Contain only strings.
2. Contain no duplicates.
3. Be **sorted in ascending Unicode code point order**. This is not UTF-16 code-unit order and not locale collation. Implementers in languages whose default string sort uses UTF-16 code units (for example JavaScript) MUST sort by code point explicitly.

A consumer MUST reject, not silently re-sort, a state whose lists violate these rules. Rejecting is what lets the STATE ID act as an integrity check.

## 5. STATE ID

The STATE ID is computed as follows:

1. Take the state object. Remove the top-level keys `state_id` and `previous_state_id` if they are present. Remove nothing else.
2. Serialize the result as **canonical JSON**:
   - Object keys sorted in ascending order at every nesting level.
   - No insignificant whitespace. The separators are exactly `,` and `:`.
   - ASCII-only output (`ensure_ascii=True`). Every character above U+007F is escaped as `\uXXXX` with lowercase hex digits. Characters above U+FFFF are escaped as a UTF-16 surrogate pair (`😀`).
   - Characters below U+0020 are escaped as `\b \f \n \r \t`, or as `\u00XX` otherwise. `"` becomes `\"` and `\` becomes `\\`. `/` is **not** escaped.
   - `true`, `false` and `null` are written as JSON literals. v1 has no numeric fields.
3. Encode the string as ASCII bytes. This is identical to UTF-8 here.
4. STATE ID = SHA-256 of those bytes, written as **64 lowercase hex characters** with no prefix.

These rules match Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.

Because `previous_state_id` is excluded, the STATE ID addresses content only. Identical boundaries have identical IDs wherever they sit in a history. Ordering is recorded by the ledger, not by the ID.

## 6. Test vector

Input state:

```json
{
  "schema": "security-state-v1",
  "target": "https://mcp.example.com/mcp",
  "tool_visibility": {
    "unauthenticated_tools": ["list_docs"],
    "authenticated_tools": ["delete_doc", "list_docs", "write_doc"]
  },
  "audience": {"enforced": true, "accepted_audiences": ["https://mcp.example.com/mcp"]},
  "origin": {"validated": true, "allowed_origins": ["https://app.example.com"]},
  "cors": {"allow_origin_wildcard": false, "allow_credentials": false, "allowed_origins": ["https://app.example.com"]}
}
```

Canonical preimage (one line):

```
{"audience":{"accepted_audiences":["https://mcp.example.com/mcp"],"enforced":true},"cors":{"allow_credentials":false,"allow_origin_wildcard":false,"allowed_origins":["https://app.example.com"]},"origin":{"allowed_origins":["https://app.example.com"],"validated":true},"schema":"security-state-v1","target":"https://mcp.example.com/mcp","tool_visibility":{"authenticated_tools":["delete_doc","list_docs","write_doc"],"unauthenticated_tools":["list_docs"]}}
```

STATE ID:

```
bb047be12442528b0cdd570f9a83b0b57ef2518f07604d18a513891057ea0f5c
```

Adding `"state_id": "bb04…"` and `"previous_state_id": null` to the object MUST NOT change this value.

Escaping vector: `{"b":"é \n/","a":"😀"}` canonicalizes to `{"a":"😀","b":"é \n/"}`.

## 7. Out of scope

- Timestamps, scanner identity, probe verdicts and coverage. See [observation-v1](observation-v1.md).
- Authenticity. A STATE ID shows that a state's content was not changed. It does not show who produced the state or that the state is true. Authenticity needs a signature, which v1 does not define.
