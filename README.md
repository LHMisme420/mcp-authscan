# mcp-authscan

Security scanner for Model Context Protocol (MCP) server deployments.

Detects zero-authentication endpoints, CORS misconfigurations, weak token validation, and other authentication/authorization failures in running MCP servers.

## Quick Start

```bash
python3 -m mcp_authscan.cli scan http://localhost:8000
```

## Installation

```bash
pip install -e .
# or
python3 -m mcp_authscan.cli scan <url>
```

## Usage

```bash
# Text report
python3 -m mcp_authscan.cli scan http://target:port --format text

# JSON report
python3 -m mcp_authscan.cli scan http://target:port --format json

# Save to file
python3 -m mcp_authscan.cli scan http://target:port --output report.json
```

## Checks

For explicit authorized endpoints without registry enumeration, automatic
uploads, or treating every HTTP 200 as a vulnerability, see
[the authorized HTTP probe](docs/authorized-scans.md).

1. **Endpoint Reachability** — Verify MCP endpoints respond
2. **SSE Authentication** — Detect zero-auth on /sse (CRITICAL)
3. **Message Endpoint Authentication** — Detect zero-auth on /message (CRITICAL)
4. **MCP Endpoint Authentication** — Detect zero-auth on /mcp (CRITICAL)
5. **CORS Configuration** — Flag wildcard Allow-Origin headers (CRITICAL)
6. **Authorization Header Validation** — Test token rejection (HIGH)

## Output

Summary of findings with risk levels, endpoints, details, and remediation guidance.

## Compliance

See [COMPLIANCE.md](COMPLIANCE.md) for CWE, OWASP Top 10, and NIST CSF mappings.

## License

MIT
