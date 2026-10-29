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
- **PASS:** /token endpoint returns `Access-Control-Allow-Origin` header (CORS working)
- **FAIL:** None (CORS headers are observations, not failures)
- **OBSERVATION:** CORS headers absent or restricted
- **NOT_OBSERVED:** Endpoint unreachable

### [5] jwks-keys
- **PASS:** /jwks endpoint returns valid JWKS (keys array, at least 1 key)
- **FAIL:** Invalid or empty JWKS
- **NOT_OBSERVED:** Endpoint unreachable, invalid_request error

### [6] password-grant
- **PASS:** /token endpoint returns error `"unsupported_grant_type"` when password grant attempted (RFC 2.1 compliance)
- **FAIL:** /token returns 200 OK (password grant accepted, deprecated vulnerability)
- **NOT_OBSERVED:** invalid_client, invalid_request, or other unexpected error

### Authorization request outcomes (probes 7 and 8)
Probes 7 and 8 send GET requests to the `authorization_endpoint`. Redirects are never followed and a returned `Location` is recorded (with `code=`, `access_token=` and `id_token=` values redacted) but never fetched.
- **Proceeded** (the request was accepted): HTTP 200; or a 3xx whose `Location`, resolved against the authorization endpoint and carrying no `error=`, is either the `redirect_uri` that was sent (exactly, or followed by its own `?`/`#` parameters, e.g. `?code=`) or a page on the authorization endpoint's own origin (scheme, host and port), taken to be the server's consent page.
- **Refused** (an OAuth error): a 4xx whose JSON body is an object carrying `"error"`; or a 3xx whose `Location` carries `error=` in its query or fragment.
- **Neither**: anything else, including a 3xx with no `Location`, a 3xx to another origin, a 4xx without a JSON error body, a 5xx, and a 3xx to the registered `redirect_uri` when a different one was sent (the server substituted its registered value, which does not show it accepted the one sent).

### [7] pkce-s256
Three requests (`response_type=code`, `client_id`, and the registered `redirect_uri` if configured) that differ only in PKCE: **A** no `code_challenge`; **B** a fresh 43-character `code_challenge` with `code_challenge_method=S256`; **C** the same challenge with `code_challenge_method=plain`. C is sent only when A was refused and B proceeded.
- **PASS:** A refused, B proceeded, C refused. The server requires PKCE and accepts only S256.
- **FAIL (HIGH):** A refused, B proceeded, C proceeded. The server accepted an authorization request using the PKCE plain method.
- **NOT_OBSERVED:** any other combination, including C neither refused nor proceeded; the detail names what each request returned. Also a request error or a target outside the allowed scope.
- **EXCLUDED:** no `authorization_endpoint` ("No authorization endpoint"), or no client id (MCPAUTHSCAN_CLIENT_ID).

### [8] redirect-uri-exact
Needs the client id and the registered redirect_uri (MCPAUTHSCAN_CLIENT_ID, MCPAUTHSCAN_REDIRECT_URI). Two requests, each with a valid S256 challenge so PKCE cannot be the cause: **P** the registered `redirect_uri`; **N** the same URI with one character (`x`) appended to its path (an empty path becomes `/x`; query and fragment kept). N is sent only when P proceeded.
- **PASS:** P proceeded, N refused. The server accepted the registered redirect_uri and refused the same URI with one character appended to its path, so it compares redirect URIs exactly.
- **FAIL (CRITICAL):** P proceeded, N proceeded. The server accepted a redirect_uri with one character appended to the registered path, so it does not compare redirect URIs exactly; nothing was sent to the returned Location.
- **NOT_OBSERVED:** P refused (no baseline; the detail carries the refusal), P neither refused nor proceeded, or N neither refused nor proceeded. Also a request error or a target outside the allowed scope.
- **EXCLUDED:** client id or redirect_uri missing ("No registered redirect_uri to compare against"), or no `authorization_endpoint` ("No authorization endpoint").

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
