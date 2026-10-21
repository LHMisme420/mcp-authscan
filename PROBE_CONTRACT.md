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

### [7] pkce-s256
- **NOT_OBSERVED:** Cannot test without registered client and authorization flow
- (Out of scope for new server assessment)

### [8] redirect-uri-exact
- **NOT_OBSERVED:** Cannot test without registered client and authorization endpoint
- (Out of scope for new server assessment)

### [9] client-auth
- **PASS:** /token endpoint returns HTTP 401 with error `"invalid_client"` when malformed Bearer token sent (RFC 6749 §5.2)
- **FAIL:** /token returns 200 OK (accepts malformed token, vulnerability)
- **NOT_OBSERVED:** Any other error (invalid_token, invalid_request, etc.), endpoint unreachable, or non-standard response

---

## Coverage Rule

For 9-probe assessment:
- **In-scope probes:** 1-6, 9 (seven probes that can run on any server)
- **Out-of-scope probes:** 7-8 (two probes requiring registered client)
- **Pass coverage:** NOT_OBSERVED ≤ 2 (only the out-of-scope probes)
- **Fail coverage:** NOT_OBSERVED > 2 → EXIT 5 (cannot fully assess server)

A server must reach verdicts on all in-scope probes to report exit 0 or 1. Insufficient coverage → EXIT 5.
