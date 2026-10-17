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

Heuristic "surface" rules (SSRF surface, PKCE-on-a-proxy, and similar) are
emitted at **INFO / needs-review**, not as confirmed vulnerabilities, so they
never trip `--fail-on`. They enumerate things worth a human's eye; confirmed
detectors keep their severity and gate the build.

### Suppressing known-good findings (source scans)

When a source finding is a reviewed false positive, silence it two ways:

```python
# authscan:ignore A4   <- on the finding line, or the line directly above it
response = requests.get(config.UPSTREAM_URL)   # bare `authscan:ignore` = all rules
```

Or list patterns in a `.authscan-ignore` file at the scan root — one
`path-glob[:RULE,RULE]` per line (`#` comments allowed; no rule suffix ignores
every rule under the glob):

```
# vendored SDK makes config-driven calls we've reviewed
src/vendor/**:A4
scripts/*.ts
```

### Taint analysis (dataflow) — `--taint`

The regex rules match shapes and *approximate* whether a call is guarded. The
optional taint engine answers the question regex can't: **does untrusted input
actually reach a dangerous sink, unsanitized?** It runs [Semgrep](https://semgrep.dev)
taint rules and emits a finding only when it traces a source→sink path with no
sanitizer in between.

```bash
pip install "mcp-authscan[taint]"          # one-time: pulls the Semgrep engine
mcp-authscan scan ./path/to/repo --taint   # or: python3 mcp_authscan.py <dir> --taint
```

It ships two detector classes today — **SSRF** (`T1-SSRF`, CWE-918) and **OS
command injection** (`T2-CMDI`, CWE-78) — across TypeScript/JavaScript, Python,
and Go. Because a real path is traced, these are HIGH-confidence detectors: they
**gate** `--fail-on`, unlike the heuristic surface rules. If Semgrep isn't
installed, `--taint` prints a note and skips rather than failing.

**Scope (be precise about this):** the OSS Semgrep taint engine is
**intra-function** — it follows a tainted value through one function body and
recognizes a sanitizer on that path, which is already beyond regex. Following a
value *across functions or files* requires the paid Semgrep Pro engine; those
flows stay heuristic review items here, not silent misses.

### SARIF output (code-scanning dashboards)

`--format sarif` emits SARIF 2.1.0 — one run, one result per finding (passed
checks are not emitted), with severities mapped for GitHub code scanning. Works
for a single target or a whole fleet.

```bash
mcp-authscan scan --targets inventory.txt --format sarif -o results.sarif
# then upload results.sarif via github/codeql-action/upload-sarif in CI
```

### Extended checks (RCE preconditions)

`--checks all` adds two opt-in, non-exploitative checks for the MCP RCE classes
documented by OX Security (April 2026), on top of the default auth/CORS checks:

- **Unauthenticated MCP config endpoint** (config → STDIO-spawn RCE class, e.g.
  LiteLLM CVE-2026-30623) — never registers a server or runs a command.
- **Missing Host/Origin validation** (DNS-rebinding precondition, e.g. MCP Java
  SDK CVE-2026-35568) — sends only a foreign `Host`/`Origin`; makes no tool calls.

```bash
mcp-authscan scan http://your-server --checks all
```

See `research/mcp_stdio_rce/` for the mocks, a standalone detector CLI, and a
lab guide for these classes.

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
