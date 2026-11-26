# MCP AuthScan v1.1.46 — Verification Receipt

Six regression tests passed against the installed
PyPI wheel, version 1.1.46, using Python 3.13.

## Verified
- Rebinding: public-first / loopback-later DNS
- IPv4-mapped IPv6 loopback refusal
- Mixed public/private DNS refusal
- HTTP 401 with Nonsense authentication scheme
- HTTP 401 without WWW-Authenticate
- HTTP 401 with valid Bearer challenge (control)

## Results
3 rebinding tests passed.
3 preflight challenge tests passed.
Overall: PASS.

## Published wheel SHA-256
19d405f2962276d8909a6f08fd02fe21349d9c52f224c3ef9e69b634f6ae1f87

## Evidence limitations
The rebinding tests establish safe behavior against
the tested fixtures, not a historical fail-before/
pass-after demonstration.

Preflight challenges use controlled mocked HTTP
responses through the actual preflight code path.

Client-test integration into the primary CLI remains
pending.

The receipt records the original local test execution.
Publishing it does not independently attest its author
or execution environment.
