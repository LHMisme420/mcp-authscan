# mcp-authscan

Security scanner for Model Context Protocol (MCP) server deployments.

Detects zero-authentication endpoints, CORS misconfigurations, weak token validation, and other authentication/authorization failures in running MCP servers.

## Authorization — read before you scan

**Reachability is not permission.** A server being publicly reachable does not
authorize you to scan it, and "open source" governs the *code* (clone and run it
yourself), not someone else's running *deployment*. This tool sends crafted
requests to probe for weaknesses; doing that against a system you are not
authorized to test is unauthorized access under laws like the US CFAA and the UK
Computer Misuse Act — **regardless of intent, and even if you only report what
you find.** Finding-and-reporting does not substitute for authorization, and
unverified scanner output is marked as spam by most bug-bounty programs.

Scan a target only if **at least one** of these is true:

- [ ] **You operate it** — your own server, staging, or lab instance.
- [ ] **You have written authorization** — a signed pentest engagement covering
      this asset.
- [ ] **It is an in-scope bug-bounty / VDP asset** AND the program policy
      **explicitly permits automated scanning**. Verify, from the live program:
  - [ ] the *specific* endpoint (not just the org) is listed in scope;
  - [ ] automated tools are allowed (many programs forbid scanners outright);
  - [ ] you are within the program's rate limits;
  - [ ] you send any required identifying header (`-H "Header: value"`) tied to
        your researcher account.

If you cannot tick a box above, do not scan — run the target locally instead
(clone the server, run it on loopback, scan your own instance). A path segment
or product name that mentions a vendor does **not** make a third-party SaaS host
that vendor's asset, and one program's scope never authorizes testing a
different vendor's infrastructure.

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

# Attach an identifying header to every request (repeatable).
# Some bug-bounty programs require a research tag tied to your account on all
# testing traffic — add it here so your scan complies with their rules.
python3 -m mcp_authscan.cli scan http://target:port -H "X-Research: your-tag"
```

After `pip install`, the `mcp-authscan` command is also on your PATH:

```bash
mcp-authscan scan http://target:port
```

### Fleet scanning (your own inventory)

Scan many targets at once — pass several URLs, or a file (one URL per line,
`#` comments allowed). Scans run concurrently and a single aggregated report is
produced.

```bash
mcp-authscan scan https://a.internal https://b.internal --format json
mcp-authscan scan --targets inventory.txt --concurrency 16 --format json -o fleet.json
```

### CI gating

`--fail-on <severity>` sets the exit code so a scan can gate a pipeline. The
process exits `1` if any finding is at or above the threshold, `2` if a target
could not be scanned, else `0`.

```bash
# Fail the build only on CRITICAL (the default)
mcp-authscan scan --targets inventory.txt --fail-on critical

# Stricter: fail on HIGH or above; disable gating with --fail-on none
mcp-authscan scan --targets inventory.txt --fail-on high
```

## Checks

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
