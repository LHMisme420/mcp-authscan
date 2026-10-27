# Probe Verdict Defects Found 2026-10-26

## Summary

Ground truth verification against committed fixture tests/test_fixture_with_findings.py on port 9002 revealed five defects in oauth_probes_v2.py that prevent the scanner from detecting known vulnerabilities.

## D1 token-cors reports PASS on error responses

The probe sends OPTIONS /token with Origin header and reads Access-Control-Allow-Origin from the response. When the server returns 501 (method not allowed), no ACAO header is present. The PASS condition is `if acao == "*"` which is false when the header is absent, so the verdict becomes PASS instead of NOT_OBSERVED.

The fixture serves `Access-Control-Allow-Origin: *` on POST /token, but the OPTIONS request gets a 501 error response with no ACAO header.

Observed: token-cors PASS against a fixture written to fail.
Owed: NOT_OBSERVED on 501, then POST /token to read the actual ACAO header.
Severity: HIGH (wildcard ACAO on token endpoint is MEDIUM; with Access-Control-Allow-Credentials: true it is HIGH).

## D2 password-grant reports inconclusive when the server accepts the grant

The verdict branch matches only `error == "unsupported_grant_type"`. A server that accepts the flow returns 200 with an access_token and no error field, so the response falls through to NOT_OBSERVED. The property is that the server rejects this flow, so acceptance is the property failing.

Observed: password-grant NOT_OBSERVED against a fixture written to be caught.
Owed: FAIL (HIGH severity) when 200 with access_token is returned.

## D3 jwks-keys cannot fail

Both branches of the status logic assign `status = "PASS"`, with the comment "always pass if data retrieved". A probe that cannot fail still counts as a pass in the coverage arithmetic, so it inflates coverage with something structurally incapable of finding anything.

Observed: jwks-keys PASS on all evaluable 200 responses.
Owed: PASS only on an evaluable 200 carrying a non-empty body.keys array.

## D4 token-cache-control fails on responses it never evaluated

An absent no-store header is treated as FAIL regardless of the status that produced the absence. This was already observed on 2026-10-21 as a LOW false positive from a 404.

Observed: Previously reported false positive when scanning non-OAuth targets that returned 404.
Owed: FAIL only on an evaluable response (one the property can actually be checked on). NOT_OBSERVED on non-evaluable responses (error statuses, non-JSON bodies, etc.).

## D6 probes bypass egress guard

Probes that make requests (token-cors, password-grant, token-cache-control, jwks-keys) call urlopen() directly without calling assert_url_is_fetchable(). Discovery applies the guard, but probes do not. A malicious target can advertise private IP addresses in OAuth endpoint metadata and cause the scanner to send requests to internal networks.

Observed: Fixture metadata can point to 169.254.169.254 and scanner will attempt connection.
Oved: Stopgap - add assert_url_is_fetchable() before each probe request. Full fix - centralized fetch() seam.

## D5 the documented PASS gate is not implemented

The written gate (PASS documentation) says 404, 405, 5xx, timeouts, connection errors, HTML and unexpected statuses all count as NOT_OBSERVED. D1, D3 and D4 each violate this gate independently.

The gate exists in the documentation and not in the code.

## Root Cause

The probes send requests directly via urlopen() without a shared response validation layer. Each probe has independent error handling, allowing inconsistent interpretations of the same status code. The documented gate exists as intended design but has no implementation.

## Proof Required

Three test runs before fix is accepted:

1. 9002 rerun: Must return exit 1 with password-grant FAIL and token-cors FAIL
2. New fixture (OPTIONS→501, /jwks→HTML): Must return NOT_OBSERVED for both probes
3. Metadata with http://169.254.169.254 token_endpoint: Must refuse with egress reason, no request sent

## Stopgap Applied (2026-10-26, not yet proven)

Added assert_url_is_fetchable() calls to four probes:
- probe_token_cache_control line 116
- probe_token_cors line 169
- probe_jwks_keys line 170
- probe_password_grant line 285

Probes now check egress guard before urlopen(). Stopgap closes D6 (egress bypass). Full fix (fetch() seam) still pending.

6 urlopen sites found in oauth_probes_v2.py by grep. 4 guards applied (lines 116, 169, 170, 285). 2 remaining unguarded (lines 297, 378, 422 — need to verify which probe is at each). 

Proof needed: Scan metadata with http://169.254.169.254 as token_endpoint. Must refuse with egress message and send no request.

## Proposed Fix

Create a fetch() seam that all probes use:
- Validates status and content-type before probe logic
- Checks against egress guard
- Returns normalized record with why_not_observed
- No probe sees a raw response, only evaluable records

Each probe declares expected_statuses for evaluable() check.

## Impact

These defects allow the scanner to miss real vulnerabilities on known-vulnerable fixtures and report false positives on non-OAuth targets.
## Guards Applied - Verified State

### assert_url_is_fetchable calls:
116:    assert_url_is_fetchable(token_endpoint, allow_private=allow_private)
169:    assert_url_is_fetchable(token_endpoint, allow_private=allow_private)
170:    assert_url_is_fetchable(jwks_uri, allow_private=allow_private)
285:    assert_url_is_fetchable(token_endpoint, allow_private=allow_private)
297:    assert_url_is_fetchable(token_endpoint, allow_private=allow_private)
378:    assert_url_is_fetchable(token_endpoint, allow_private=allow_private)
422:    assert_url_is_fetchable(token_endpoint, allow_private=allow_private)

### urlopen calls:
5:from urllib.request import Request, urlopen
128:            with urlopen(req, timeout=5) as resp:
186:            with urlopen(req, timeout=5) as resp:
247:        with urlopen(req, timeout=5) as resp:
298:            with urlopen(req, timeout=5) as resp:
380:            with urlopen(req, timeout=5) as resp:
425:        with urlopen(req, timeout=5) as resp:

## Proof Required

Test with metadata advertising http://169.254.169.254 as token_endpoint.
Scanner must refuse with egress reason and exit, not proceed to verdict. Refusal must reach the exit, not be caught by except block.
