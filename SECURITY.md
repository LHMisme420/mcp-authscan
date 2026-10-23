# Security Policy

## Reporting a Vulnerability
Report suspected vulnerabilities in mcp-authscan to lhmisme2011@gmail.com.
Please do not open public issues for security reports. Expect an initial
response within 7 days. Coordinated disclosure preferred; credit given
unless you request otherwise.

## Scope
mcp-authscan runs in two modes and this policy covers both.

**Repository review** reads a target's source tree and configuration. In this
mode the scanner does not execute target code, import target modules, or run
target tests.

**Live server scanning** sends authenticated and unauthenticated HTTP(S) probe
traffic to the host the operator names: an MCP `initialize` request, the
RFC 9728 → RFC 8414 discovery chain (including the resource-metadata and
authorization-server documents whose URLs the target supplies), and OAuth
endpoint probes (token endpoint, PKCE, redirect-uri, client-auth, key rotation,
CORS). This mode is network-facing by design, so only point it at systems you
operate or are explicitly authorized to test.

Reports about the scanner's own behavior are in scope: false negatives on seed
findings, unsafe file handling during a repository review, unsafe request
handling during a live scan, and crashes, hangs or resource exhaustion caused by
a malformed or hostile target.
