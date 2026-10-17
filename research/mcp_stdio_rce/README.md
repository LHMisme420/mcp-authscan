# MCP STDIO "config → command" RCE — local research harness

A self-contained, **loopback-only** harness for studying and detecting the
MCP STDIO command-execution class documented by OX Security (disclosed April
2026). Nothing here targets third-party systems; it reproduces the *pattern*
so you can understand it, detect it on servers **you operate or are authorized
to test**, and verify a fix.

## The vulnerability class

MCP's STDIO transport spawns a child process directly from configuration, with
no validation step between config and `spawn`. Two consequences:

1. **Execution at spawn time, not request time.** A command runs when a server
   is *registered/configured*, so a front-door auth proxy never sees a
   "request" to block. Hardening that sits in front of the app (e.g. Flowise)
   can be bypassed for this reason.
2. **Unauthenticated config interfaces → RCE.** Several products exposed the
   MCP-config/registration interface without authentication, letting a remote
   attacker register a malicious STDIO server and trigger execution by starting
   an agent session.

Representative references:
- OX Security advisory — *MCP Supply Chain Advisory: RCE Across the AI Ecosystem*
- LiteLLM authenticated MCP-server-creation RCE — **CVE-2026-30623**
  (fixed in v1.83.6-nightly / v1.83.7-stable)
- MCP Java SDK **DNS rebinding** — **CVE-2026-35568** (browser-reachable local
  MCP server; same family as the MCP Inspector localhost issue)

Product patches close specific entry points; they do **not** change the STDIO
protocol behavior itself.

## Files

| File | What it is |
|---|---|
| `vulnerable_router.py` | Minimal mock of the antipattern: unauth registry listing + unauth registration that spawns the command at register time. |
| `hardened_router.py` | The mitigated counterpart: auth on all config endpoints + a launcher allowlist and metacharacter rejection. |
| `detector.py` | Standalone CLI around the **safe** detectors (JSON output). The detection logic itself lives in the installed package at `mcp_authscan/rce_checks.py`, so the main scanner reuses it via `mcp-authscan scan <url> --checks all`. Two checks: (a) the unauthenticated-config endpoint (never registers a server or submits a command), and (b) missing Host/Origin validation, the DNS-rebinding precondition (sends only foreign `Host`/`Origin` headers, makes no tool calls). |

Tests: `../../tests/test_stdio_rce_research.py` (detector fires on the
vulnerable mock, stays clean on the hardened one, and a benign demo proves
config-time execution by writing a marker file).

## Usage (local only)

```bash
# 1. stand up the vulnerable mock on loopback
python3 research/mcp_stdio_rce/vulnerable_router.py --port 9201 &

# 2. detect the unauth-config condition (no exploitation)
python3 research/mcp_stdio_rce/detector.py http://127.0.0.1:9201

# 3. compare against the hardened mock
ROUTER_TOKEN=secret python3 research/mcp_stdio_rce/hardened_router.py --port 9202 &
python3 research/mcp_stdio_rce/detector.py http://127.0.0.1:9202   # -> clean
```

`detector.py` runs two safe checks and prints any findings as JSON:

- **Unauthenticated config endpoint** — a config/registry listing served without
  auth, or a registration endpoint that processes an unauthenticated request.
- **Missing Host/Origin validation (DNS-rebinding precondition, CVE-2026-35568
  family)** — sends a foreign `Host` + `Origin` to endpoints that already answer
  on the real host; if the server still processes them instead of rejecting
  (400/403/421), it does not pin Host/Origin and a rebound browser could reach
  it. The probe makes no tool calls and changes no state. The fix is to validate
  `Host`/`Origin` against an allowlist (loopback + known hostnames).

## Reproducing against real LiteLLM (isolated lab)

Do this in a throwaway VM/container with **no** network exposure, on software
you are running yourself:

1. Create an isolated env and pin a pre-fix version:
   `pip install 'litellm<1.83.6'` (check the advisory for exact affected range).
2. Start it locally and point `detector.py` at its MCP-config endpoint to
   observe the unauthenticated-config signal.
3. Upgrade to the fixed release (`>=1.83.7`) and re-run — the signal should
   clear. That before/after is the useful, publishable result.

Confirming a fix on your own instance is legitimate research. Pointing any of
this at someone else's deployment is not — see below.

## Authorization

Reachability is not permission. Run the detector only against:
- systems you operate, or
- an in-scope bug-bounty asset whose policy **explicitly permits automated
  testing**, within its rate limits.

Finding-and-reporting does not substitute for authorization, and probing for
RCE on systems you don't own is unauthorized access regardless of intent.
Follow the coordinated-disclosure model the original researchers used: reproduce
locally, report to the vendor, wait for a patch.
