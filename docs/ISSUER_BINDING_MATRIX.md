| client | version | verdict | evidence |
| --- | --- | --- | --- |
| fastmcp | 4.1.1 | FAIL | credentials sent to an issuer that did not match the protected resource, captured at /token |
| fastmcp | 4.1.2 | PASS | refused with issuer mismatch before presenting any credential |
| mcp (Python) | 2.3.0 | PASS | expectedIssuer set: refused on issuer mismatch, no credential reached /token; unbound default run leaked client_secret_basic to /token |
| @modelcontextprotocol/sdk (TypeScript) | 1.32.2 | PASS | expectedIssuer set: refused on issuer mismatch, no credential reached /token; unbound default run leaked client_secret_basic to /token |
