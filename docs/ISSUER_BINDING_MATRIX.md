| client | version | verdict | evidence |
| --- | --- | --- | --- |
| fastmcp | 4.1.1 | FAIL | credentials sent to an issuer that did not match the protected resource, captured at /token |
| fastmcp | 4.1.2 | PASS | refused with issuer mismatch before presenting any credential |
| mcp (Python) | 2.3.0 | PASS | expectedIssuer set: refused on issuer mismatch, no credential reached /token; unbound default run leaked client_secret_basic to /token |
| mcp (Python) | 1.30.0 | PASS | dedicated venv with mcp 1.30.0 and no fastmcp; consistent flow reached /register, /token with the full SDK body, then /mcp with a Bearer, 1 token hit; mismatched refused with OAuthFlowError at the issuer check, 0 token hits, no authorize_url |
| @modelcontextprotocol/sdk (TypeScript) | 1.32.2 | PASS | expectedIssuer set: refused on issuer mismatch, no credential reached /token; unbound default run leaked client_secret_basic to /token |
| mcp (Python) | 1.29.1 | FAIL | expectedIssuer set: credential still sent to the non-matching token endpoint, Basic auth captured at /token; unbound default run the same |
| mcp (Python) | 1.30.0 | PASS | expectedIssuer set: refused on issuer mismatch, no credential reached /token; unbound default run leaked client_secret_basic to /token |
| mcp (Python) | 2.1.1 | FAIL | expectedIssuer set: credential still sent to the non-matching token endpoint, Basic auth captured at /token; unbound default run the same |
| mcp (Python) | 2.2.0 | PASS | expectedIssuer set: refused on issuer mismatch, no credential reached /token; unbound default run leaked client_secret_basic to /token |

