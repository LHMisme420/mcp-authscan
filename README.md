# VATA MCP Security Scanner — Lab Demonstration & Ecosystem Baseline

**Receipts Over Promises**

---

## Overview

VATA (Vulnerability Assessment and Tracking Archive) is an independent AI security research program running a comprehensive audit of the MCP (Model Context Protocol) ecosystem and baseline security analysis of official MCP reference implementations.

This repository contains:
1. **mcp_authscan.py** — MCP security scanner for testing OAuth, CORS, authentication, and protocol-level vulnerabilities
2. **Lab credibility demonstration** — Before/after validation showing the scanner detects vulnerabilities in intentionally vulnerable servers and confirms fixes
3. **Reference server security analysis** — Official MCP SDK vulnerability baseline documentation

---

## Quick Start

**Install from source (main branch — latest fixes):**

```bash
git clone https://github.com/LHMisme420/mcp-authscan.git
cd mcp-authscan
pip install -e .
```

**Run live OAuth server assessment:**

```bash
mcp-authscan https://api.example.com/mcp \
  --authorized-by "Your Name" \
  --auth-basis "written consent" \
  --contact "your.email@example.com"
```

**Output:**
- Human-readable security report with PASS/FAIL verdicts
- OAuth endpoint configuration analysis (RFC 9728 → RFC 8414)
- Probe results summary with evidence strings
- Report hash (SHA256) with scan timestamp for integrity verification

**Exit codes:**
- `0` — Scan completed. No FAIL verdicts at or above `--fail-on` threshold (default: high).
- `1` — Scan completed. FAIL verdicts detected at or above `--fail-on` threshold.
- `2` — Authorization validation failed (refused, fail-closed, no network calls made). Validation runs before reachability check — authorization is checked before the scanner touches the network.
- `3` — Target unreachable (connection refused or network error).
- `4` — Target is not a valid MCP server (preflight check failed).
- `5` — Server not assessable: discovery incomplete, zero verdicts reached, OR too many probes NOT_OBSERVED (>2 in 9-probe set, meaning insufficient coverage).
- `6` — Usage error (malformed arguments).

**Verdict types:** Only **FAIL** verdicts vote for the `--fail-on` threshold. **PASS** verdicts show server compliance. **NOT_OBSERVED** (endpoints unreachable) do not count toward coverage. **EXCLUDED** probes require client credentials and are not assessed without registration.

Note: Severity levels are reported in the security report. Use `--fail-on` to set the threshold:

```bash
# Default: --fail-on high (exit 1 if HIGH or CRITICAL findings)
mcp-authscan https://your-server/mcp ...

# Only fail on CRITICAL findings (exit 0 for HIGH/MEDIUM/LOW)
mcp-authscan https://your-server/mcp ... --fail-on critical

# Fail on any findings (MEDIUM, HIGH, or CRITICAL)
mcp-authscan https://your-server/mcp ... --fail-on medium
```

**Current version:** v1.1.3 (main branch)

---

## Lab Demonstration: Scanner Credibility

### Principle

> A tool that finds nothing on good code and something on bad code is a tool. One that only ever reports is a script.

This lab demonstrates the VATA MCP Security Scanner's methodology using controlled test servers in different security postures.

### Test Setup

**Two test states with identical endpoints:**
- **State 1**: Zero authentication + CORS wildcard
- **State 2**: Bearer token authentication required

### Results

**SCAN 1: Vulnerable State**
- Target: `http://127.0.0.1:5004/tools/list`
- Configuration: Zero auth, CORS wildcard
- Scanner findings: **2 findings**
  - Finding 1: Unauthenticated Access (CRITICAL)
  - Finding 2: CORS Wildcard (MEDIUM)
- HTTP evidence: GET without auth header → **HTTP 200 OK** with tool data in response

**SCAN 2: Fixed State**
- Target: Same endpoint
- Configuration: Bearer token required
- Scanner findings: **Findings resolved**
  - Finding 1: Authentication now required (RESOLVED)
  - Finding 2: CORS wildcard present but endpoint protected by auth (INFO)
- HTTP evidence: GET without auth header → **HTTP 401 Unauthorized**, no data

### Key Difference: State Change Detection

| Aspect | State 1 | State 2 | Detected |
|--------|---------|---------|----------|
| Authentication | Not required (200) | Required (401) | ✓ Yes |
| Readable Data | Tool data returned | No data (401) | ✓ Yes |
| HTTP Status | 200 OK | 401 Unauthorized | ✓ Yes |
| CORS Header | Present (*) | Still present (*) | ✓ Yes |
| Severity | CRITICAL findings | Findings resolved | ✓ Yes |

**Reproducibility**: Run the scanner against identical endpoints in different security postures. The scanner detects the state change through HTTP status codes (200 vs 401) and corresponding finding changes (CRITICAL vs RESOLVED).

---

## MCP Reference Server Security Analysis

### Scope

**Repository:** modelcontextprotocol/python-sdk  
**Commit tested:** 9972c21aa42054fb1450c5fc614761ed11847ec6  
**Package version:** 2.2.0 (released September 7, 2026)  
**Test date:** October 2026

### Affected Implementations

- Memory server (multi-client data isolation, path traversal)
- Filesystem server (multi-client file access)
- Everything server (environment variable disclosure)
- SSE transport (zero-auth with CORS wildcard)
- HTTP streamable transport (zero-auth with CORS wildcard)

### Findings Summary

#### Finding 1: Multi-Client Data Isolation Gap (CRITICAL)

**Root cause:** MCP protocol initialization message includes `clientInfo` field containing only name and version. There is no standard mechanism for servers to distinguish between different clients in subsequent messages, nor any standard protocol field for propagating unique client identity in forwarded requests.

**Attack:** Client A stores sensitive data → Client B on same server calls `read_memory()` → receives Client A's data.

**Why it matters:** Every MCP server developer copies this reference code. If the baseline has no client isolation, the pattern propagates.

#### Finding 2: Zero-Auth Endpoints with Wildcard CORS (CRITICAL)

**Issue:** Reference implementations expose endpoints with:
1. Zero authentication required
2. CORS wildcard (`Access-Control-Allow-Origin: *`)

**Attack:** Any website the server operator visits can make cross-origin requests to the MCP server and call tools without authentication.

**Why it matters:** Developers copying reference transport code inherit this pattern.

#### Finding 3: Unauthenticated Environment Variable Disclosure (MODERATE)

**Affected server:** Everything server  
**Issue:** Server exposes environment variables via unauthenticated endpoint.

#### Finding 4: Path Traversal via MEMORY_FILE_PATH (HIGH)

**Affected server:** Memory server  
**Issue:** MEMORY_FILE_PATH parameter accepts relative paths without normalization.

#### Finding 5: Bearer Token Timing Attack in Authentication Examples (HIGH)

**Location:** Official SDK authentication tutorials  
**Issue:** Uses timing-unsafe token comparison (`==` instead of `hmac.compare_digest()`)

**Why it matters:** Developers copying example code inherit the vulnerability. Attackers can extract Bearer tokens character-by-character via timing side-channels.

### Systemic Issue: Missing Client Identification

**Two of the five findings stem from a single protocol design gap: absence of standard client identification.**

The MCP specification includes `clientInfo` in the initialize message (name and version only). This is informational. There is no standard field for unique client identification, and no mechanism for propagating that identity through the protocol when requests are forwarded.

**Why this matters:**
- **Multi-client servers** (Finding 1): Cannot distinguish clients; all share state
- **Zero-auth endpoints** (Finding 2): Cannot restrict access by client identity; all clients have equal access

**Findings 3, 4, and 5** are independent implementation issues unrelated to client identification.

### Filing Status

All 5 vulnerabilities reported to modelcontextprotocol maintainers via GitHub Security Advisory process (October 2026). Awaiting publication.

---

## Why This Matters More Than Single-Vendor Findings

**Single Vendor Finding:** One vendor had a security gap. Vendor fixes it, problem solved locally.

**MCP Reference Servers:** Protocol baseline code has gaps. Everyone copying this code inherits the pattern. When developers build MCP servers, they start with the reference implementations.

**The protocol baseline becomes the ecosystem baseline.**

---

## Scanner Implementation

- **Language:** Python 3
- **Methodology:** HTTP request/response analysis
- **Auth detection:** Sends requests with and without Authorization header, observes HTTP status code
- **CORS detection:** Looks for Access-Control-Allow-Origin header in response
- **Protocol testing:** Checks `/initialize`, `/tools/list`, `/tools/call`, `/resources/list`, `/sse` endpoints

---

## How to Verify

### Lab Demonstration (Before/After Validation)

```bash
# Vulnerable server
python3 vuln_zero_auth.py &
mcp-authscan http://127.0.0.1:5004 \
  --authorized-by "Your Name" \
  --auth-basis "written consent" \
  --contact "your.email@example.com"
# Output: CRITICAL finding on /tools/list

# Fixed server (same port, different process)
pkill -f vuln_zero_auth
python3 vuln_zero_auth_fixed.py &
mcp-authscan http://127.0.0.1:5004 \
  --authorized-by "Your Name" \
  --auth-basis "written consent" \
  --contact "your.email@example.com"
# Output: INFO level (MEDIUM/LOW findings only)
# Exit: 0 (no HIGH/CRITICAL findings)
```

### Reference Server Analysis

The reference server findings are verifiable against:
- Commit: `9972c21aa42054fb1450c5fc614761ed11847ec6` in modelcontextprotocol/python-sdk
- Package version: `2.2.0` from PyPI (released September 7, 2026)

Any developer can check out that exact commit and reproduce the findings.

---

## Methodology: Receipts Over Promises

VATA research follows a strict "Receipts Over Promises" methodology:
- All findings backed by reproducible evidence
- Before/after validation (not theory)
- Public reference implementations tested
- Exact commit hashes and versions documented
- Reproducible scanning methodology

---

## About VATA

**Vulnerability Assessment and Tracking Archive** — Independent AI security research by Leroy (lhmisme2011@gmail.com)

- **GitHub:** LHMisme420
- **ORCID:** 0009-0002-3115-534X
- **Dashboard:** lhmisme420.github.io/VATA-SCORES-0311
- **Publications:** Zenodo.org

---

*Lab demonstration and reference server analysis: October 2026*  
*Scanner: mcp_authscan.py*  
*Methodology: HTTP request/response analysis + protocol specification review*  
*Classification: Research publication (Zenodo), not responsible disclosure of production systems*

