# Probe Pass Conditions — What Was Tested

Each probe defines when it reaches a PASS verdict (compliance confirmed) vs FAIL (vulnerability found) vs NOT_OBSERVED (unable to test).

## OAuth Server Probes (RFC 6749 / RFC 8414)

### [1] issuer-identity
- **PASS:** Authorization server metadata includes `issuer` field matching server URL
- **FAIL:** Missing issuer field in metadata
- **NOT_OBSERVED:** Cannot fetch metadata

### [2] resource-binding
- **PASS:** Protected Resource Metadata (RFC 9728) includes `resource` field matching scanned MCP endpoint URL
- **FAIL:** Missing resource field in PRM
- **NOT_OBSERVED:** Cannot fetch metadata

### [3] token-cache-control
- **PASS:** /token endpoint returns `Cache-Control: no-cache` header
- **FAIL:** Missing or incorrect Cache-Control header
- **NOT_OBSERVED:** Endpoint unreachable, no response, or invalid_request error

### [4] token-cors
Asks whether a page on a hostile origin could read a token endpoint response. Every request carries `Origin: https://hostile.example.com` and never follows a redirect. There are two modes.

**Default mode (no flag).** One POST to the `token_endpoint`: `grant_type=client_credentials` with `MCPAUTHSCAN_CLIENT_ID` (and `MCPAUTHSCAN_CLIENT_SECRET` if set) when the environment supplies a client, otherwise `grant_type=invalid`.
- **PASS:** a 2xx response with no `Access-Control-Allow-Origin` (ACAO), or with an ACAO naming some other origin
- **FAIL (HIGH):** a 2xx response with ACAO `*`, or ACAO echoing the hostile origin
- **FAIL (CRITICAL):** a 2xx response echoing the hostile origin with `Access-Control-Allow-Credentials: true`
- **NOT_OBSERVED:** a non-2xx response with a JSON error body, a 5xx, a request outside the allowed scope, or a failed request
- **EXCLUDED:** no `token_endpoint` advertised; or a 4xx without a JSON error body

**Acquired-token mode (`--acquire-token`, off by default, since probe set 2026.10.30).** The probe obtains a real access token through an *attended* authorization-code exchange (a person approves consent in a browser) and tests the cross-origin read on the response that carries it. Without the flag the scanner never prompts and never reads stdin.
1. Client: the client registered for this assessment (see "Client source for probes 7 and 8"), else `MCPAUTHSCAN_CLIENT_ID` with `MCPAUTHSCAN_REDIRECT_URI` (and `MCPAUTHSCAN_CLIENT_SECRET` if set). The registered redirect R is that client's exact redirect URI.
2. A fresh PKCE verifier, its S256 challenge, and a random `state`.
3. The scanner builds the authorization URL (`authorization_endpoint` with `response_type=code`, `client_id`, `redirect_uri`=R, `code_challenge`, `code_challenge_method=S256`, `state`), prints it to stderr with instructions, and waits for one line on stdin. The scanner itself sends no request to the `authorization_endpoint`.
4. The person opens the URL in a browser and approves (for example by entering the server owner's passphrase on the consent page). The browser lands on R with the code in the address bar; nothing listens on R and the page failing to load is expected. The person pastes that full address and presses Enter.
5. The scanner checks the pasted address: its scheme, host, port and path must equal R exactly, its `state` must equal the `state` sent, and it must carry a `code`. The pasted address is never fetched.
6. One POST to the `token_endpoint` (`grant_type=authorization_code`, `code`, `redirect_uri`=R, `client_id`, `code_verifier`) carrying the hostile `Origin`, never following a redirect. This response is the cross-origin read the verdict is taken from.
7. The access token (and any refresh token) is held in memory only and revoked at the advertised `revocation_endpoint` (form POST: `token`, `token_type_hint`, `client_id`) before the report prints; then it is discarded. The revocation result is recorded per token as "<token type> <result>" (for example "access_token HTTP 200; refresh_token HTTP 503 error=temporarily_unavailable"), with the same result forms as client revocation below, or "not attempted: no revocation_endpoint advertised". A token is revoked only when its response is 2xx. Otherwise (a non-2xx such as a 5xx or a 401 asking for client authentication the scanner does not have, a request outside the allowed scope, a failed request, or no `revocation_endpoint` advertised) the token is still valid on the server: the scanner prints to the terminal (stderr) `[!] TOKEN STILL LIVE: <token types> issued by <authorization server> to client_id <client_id> not revoked (<revocation result>); revoke on the server`, and the report says the same (text: `Token Status: STILL LIVE on the server (<token types> not revoked; revocation: <revocation result>). Revoke on the server.`; JSON: `token_still_live: true`). When every token obtained was revoked the report says `Token Status: revoked` (`token_still_live: false`); when no token was obtained (default mode, or acquired mode that ended without a token) it says `Token Status: none acquired` (`token_still_live: null`). Only the token type and what the revocation returned are printed, never the token value. The revocation result is part of the detail and never changes the verdict or the exit code.

The token, the PKCE verifier, the authorization code and the pasted address are never printed (the pasted line is not echoed), logged, written to the report or JSON, or included in an exception string: the recorded body has `access_token`, `refresh_token`, `id_token`, `client_secret` and `registration_access_token` values replaced by `[redacted]`, any recorded `Location` has `code` redacted, and failed requests are reported by exception type only. The printed authorization URL carries only the challenge and `state`, never the verifier.

Verdicts in acquired-token mode, from the token response:

| Token response | Verdict |
|---|---|
| 2xx, ACAO `*`, no `Access-Control-Allow-Credentials: true` | FAIL (HIGH) |
| 2xx, ACAO `*`, `Access-Control-Allow-Credentials: true` | FAIL (CRITICAL) |
| 2xx, no ACAO | PASS |
| anything else (including an ACAO naming an origin, echoed or not, and any non-2xx) | NOT_OBSERVED |

Acquired-token mode reaches no verdict, and names why, when no token can be obtained. Each case below is one prompt and one pasted line; the scanner never re-prompts, loops or retries:
- **EXCLUDED:** no `token_endpoint`; no `authorization_endpoint`; no client (registration supplied none and `MCPAUTHSCAN_CLIENT_ID`/`MCPAUTHSCAN_REDIRECT_URI` are not both set).
- **NOT_OBSERVED, limitation "Consent not completed: no redirect address pasted":** an empty line, end of input, or a failure reading stdin.
- **NOT_OBSERVED, limitation "Consent refused at the authorization server":** the pasted address carries `error=` (for example `error=access_denied`); the detail names the error code.
- **NOT_OBSERVED, limitation "Pasted address is not the registered redirect":** the scheme, host, port or path differ from R.
- **NOT_OBSERVED, limitation "Pasted address state does not match the request":** `state` missing or different.
- **NOT_OBSERVED, limitation "Pasted address carries no authorization code".**
- **NOT_OBSERVED:** a failed token exchange, a request outside the allowed scope, or a failed request.

### [5] jwks-keys
- **PASS:** /jwks endpoint returns valid JWKS (keys array, at least 1 key)
- **FAIL:** Invalid or empty JWKS
- **NOT_OBSERVED:** `jwks_uri` outside the allowed scope (nothing sent)
- **EXCLUDED** (prerequisite missing): no `jwks_uri` in the authorization server metadata (limitation "No JWKS endpoint", nothing sent); or the `jwks_uri` request failed or its body is not JSON (detail "Cannot reach JWKS endpoint"). A server that issues opaque access tokens and publishes no `jwks_uri` (for example FlowState, whose metadata comes from the MCP Python SDK's `build_metadata`, which never sets `jwks_uri`) stays EXCLUDED here; the scanner never infers keys from elsewhere.

### [6] password-grant
- **PASS:** /token endpoint returns error `"unsupported_grant_type"` when password grant attempted (RFC 2.1 compliance)
- **FAIL:** /token returns 200 OK (password grant accepted, deprecated vulnerability)
- **NOT_OBSERVED:** invalid_client, invalid_request, or other unexpected error

### Authorization request outcomes (probes 7 and 8)
Probes 7 and 8 send GET requests to the `authorization_endpoint`. Redirects are never followed and a returned `Location` is recorded (with `code=`, `access_token=` and `id_token=` values redacted) but never fetched.
- **Proceeded** (the request was accepted): HTTP 200; or a 3xx whose `Location`, resolved against the authorization endpoint and carrying no `error=`, is either the `redirect_uri` that was sent (exactly, or followed by its own `?`/`#` parameters, e.g. `?code=`) or a page on the authorization endpoint's own origin (scheme, host and port), taken to be the server's consent page.
- **Refused** (an OAuth error): a 4xx whose JSON body is an object carrying `"error"`; or a 3xx whose `Location` carries `error=` in its query or fragment.
- **Neither**: anything else, including a 3xx with no `Location`, a 3xx to another origin, a 4xx without a JSON error body, a 5xx, and a 3xx to the registered `redirect_uri` when a different one was sent (the server substituted its registered value, which does not show it accepted the one sent).

### Client source for probes 7 and 8 (since probe set 2026.10.30)
Probes 7 and 8 need a client. The scanner resolves one once per assessed authorization server, in this order, and every probe that needs a client uses the same one:
1. **Dynamic client registration (RFC 7591).** When the metadata advertises both `authorization_endpoint` and `registration_endpoint`, the scanner sends a POST to the `registration_endpoint` with a JSON body: `client_name` "mcp-authscan", `redirect_uris` [R], `grant_types` ["authorization_code"], `response_types` ["code"], `token_endpoint_auth_method` "none". R is chosen and controlled by the scanner, from this ordered list of loopback redirects (RFC 8252), constant `REDIRECT_CANDIDATES` in the code:
   1. `http://localhost/mcp-authscan/callback`
   2. `http://127.0.0.1/mcp-authscan/callback`
   3. `http://[::1]/mcp-authscan/callback`

   No port is given: nothing listens on any of them and the scanner never fetches them (RFC 8252 7.3 lets a loopback redirect take any port at request time, so a server that requires one is not assumed). The first candidate is sent first. When the registration is refused for the redirect, meaning a 4xx whose JSON body carries `"error": "invalid_redirect_uri"` (RFC 7591 3.2.2), the scanner sends one more registration with the next candidate; any other refusal, and the last candidate's refusal, ends registration. At most three registration requests are sent. Registration succeeds when the response is 2xx, its body is a JSON object with a non-empty `client_id`, and, if the body lists `redirect_uris`, R is among them exactly. The probes then use the returned `client_id` and exactly R. The report lists every candidate tried with its result and names the accepted one. Any `client_secret` or `registration_access_token` in the response is held in memory only, never printed, logged, or written to the report or JSON. The registration request never follows a redirect.
2. **Environment.** Otherwise `MCPAUTHSCAN_CLIENT_ID` and `MCPAUTHSCAN_REDIRECT_URI`.
3. **EXCLUDED.** Otherwise the probe is EXCLUDED with the limitation below that names the missing prerequisite. When the metadata advertises an `authorization_endpoint`, the record's detail also says why registration did not supply a client: "Dynamic client registration unavailable: " followed by one of
   - "no registration_endpoint advertised"
   - "registration_endpoint outside allowed scope"
   - "registration returned HTTP <status>" (plus " error=<error>" when the body carries one)
   - "registration response carried no client_id"
   - "registration response did not list the scanner's redirect_uri <R>"
   - "registration refused every redirect candidate: HTTP <status> error=invalid_redirect_uri" (all three candidates refused for the redirect)
   - "registration request failed: <exception type>"

**Revocation.** When a client was registered, the scanner revokes it after the last probe that uses it and before the report prints: one form POST to the advertised `revocation_endpoint` with `client_id`, plus `token` set to the `registration_access_token` when the registration returned one. Redirects are never followed. The result is recorded as "HTTP <status>" (plus " error=<error>" when the body carries one), "revocation_endpoint outside allowed scope", "request failed: <exception type>", or "not attempted: no revocation_endpoint advertised". Revocation succeeded only when the response is 2xx. Otherwise (a non-2xx such as a 5xx or a 401 asking for client authentication the scanner does not have, a request outside the allowed scope, a failed request, or no `revocation_endpoint` advertised) the client is still registered on the server: the scanner prints to the terminal (stderr) `[!] CLIENT STILL LIVE: client_id <client_id> registered at <authorization server> was not revoked (<revocation result>); remove it on the server`, and the report says the same (text: `Client Status: STILL LIVE on the server`; JSON: `client_still_live: true`). The `client_id` may be printed; the `client_secret` and `registration_access_token` never are. A failed or skipped revocation never changes a probe verdict or the exit code. Note: RFC 7009 defines the revocation endpoint for tokens; deleting a registered client is RFC 7592 (DELETE on `registration_client_uri`), which the scanner does not send.

**Report.** The text report prints a CLIENT REGISTRATION block for each assessed authorization server: whether a client was registered (and, if not, why), the redirect candidates tried and the result of each, the client source (registered, environment, or none), the client_id, the redirect_uri used, what the revocation returned, whether the registered client is revoked or STILL LIVE on the server, and whether a token obtained by token-cors [4] (`--acquire-token`) is revoked, STILL LIVE on the server, or none was acquired (`Token Status:` line). The JSON carries the same under `client_registration` (`redirect_candidates_tried`: list of {`redirect_uri`, `result`}; `client_still_live`: true, false, or null when no client was registered; `token_revocation`: the per-token revocation result, or null when no token was obtained; `token_still_live`: true, false, or null when no token was obtained). Server-issued client ids differ on every run, so this block is not covered by the report hash.

### [7] pkce-s256
Three requests (`response_type=code`, `client_id`, and the `redirect_uri` from the client source above, if there is one) that differ only in PKCE: **A** no `code_challenge`; **B** a fresh 43-character `code_challenge` with `code_challenge_method=S256`; **C** the same challenge with `code_challenge_method=plain`. C is sent only when A was refused and B proceeded.
- **PASS:** A refused, B proceeded, C refused. The server requires PKCE and accepts only S256.
- **FAIL (HIGH):** A refused, B proceeded, C proceeded. The server accepted an authorization request using the PKCE plain method.
- **NOT_OBSERVED:** any other combination, including C neither refused nor proceeded; the detail names what each request returned. Also a request error or a target outside the allowed scope.
- **EXCLUDED** (nothing is sent; checked in this order):
  - no `authorization_endpoint` in the server metadata: limitation "No authorization endpoint".
  - no client from registration and no client id in the environment (MCPAUTHSCAN_CLIENT_ID not set): limitation "No client_id to build an authorization request (MCPAUTHSCAN_CLIENT_ID not set)"; the detail names why registration did not supply one. This exclusion is part of the contract: an authorization request cannot be built without a client id, and the probe never invents one.

### [8] redirect-uri-exact
Needs a client id and its registered redirect_uri, from the client source above (a registered client and R, else MCPAUTHSCAN_CLIENT_ID and MCPAUTHSCAN_REDIRECT_URI). Two requests, each with a valid S256 challenge so PKCE cannot be the cause: **P** the registered `redirect_uri`; **N** the same URI with one character (`x`) appended to its path (an empty path becomes `/x`; query and fragment kept). N is sent only when P proceeded.
- **PASS:** P proceeded, N refused. The server accepted the registered redirect_uri and refused the same URI with one character appended to its path, so it compares redirect URIs exactly.
- **FAIL (CRITICAL):** P proceeded, N proceeded. The server accepted a redirect_uri with one character appended to the registered path, so it does not compare redirect URIs exactly; nothing was sent to the returned Location.
- **NOT_OBSERVED:** P refused (no baseline; the detail carries the refusal), P neither refused nor proceeded, or N neither refused nor proceeded. Also a request error or a target outside the allowed scope.
- **EXCLUDED** (nothing is sent; checked in this order):
  - no `authorization_endpoint` in the server metadata: limitation "No authorization endpoint". This exclusion is part of the contract, as for [7]: there is nowhere to send P and N.
  - no client from registration, and client id or redirect_uri missing from the environment (MCPAUTHSCAN_CLIENT_ID or MCPAUTHSCAN_REDIRECT_URI not set): limitation "No registered redirect_uri to compare against"; the detail names why registration did not supply one.

### [9] client-auth
- **PASS:** /token endpoint returns HTTP 401 with error `"invalid_client"` when malformed Bearer token sent (RFC 6749 §5.2)
- **FAIL:** /token returns 200 OK (accepts malformed token, vulnerability)
- **NOT_OBSERVED:** Any other error (invalid_token, invalid_request, etc.), endpoint unreachable, or non-standard response

---

## Coverage Rule

For 9-probe assessment:
- **In-scope probes:** 1-6, 9 (seven probes that can run on any server)
- **Out-of-scope probes:** 7-8 (two probes requiring registered client)
- **Pass coverage:** EXCLUDED ≤ 2 (only the out-of-scope probes)
- **Fail coverage:** EXCLUDED > 2 → EXIT 5 (cannot fully assess server)

A server must reach verdicts on all in-scope probes to report exit 0 or 1. Insufficient coverage → EXIT 5.

**Summary wording for EXCLUDED.** The report summary prints one line per EXCLUDED probe with its reason, the same way it prints NOT OBSERVED probes:

```
EXCLUDED (<n>, prerequisite missing, never sent):
  <probe name>: <limitation>[; <detail>]
```

For example `  jwks-keys: No JWKS endpoint`. When a record has neither, the reason reads `(no reason recorded)`.

## Amendment 2026-10-29 (probe set 2026.10.31)
password-grant: PASS on any 4xx carrying a named OAuth error with no token issued, except invalid_grant, which means the grant was parsed and stays NOT_OBSERVED.
token-cors: a non-verdict records the status and says the check was not judged; the ACAO value stays in header evidence, never in the verdict line.
