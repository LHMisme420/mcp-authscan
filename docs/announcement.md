# mcp-authscan — launch announcement

## In-feed teaser post (what people see first — post this, link the article)

Everyone's rushing to plug AI agents into everything via MCP.

Almost nobody's checking whether those MCP servers require a password.

I got tired of guessing, so I built an open-source scanner that tells you in seconds. Here's what it found, how it works, and why "it's just internal" is not a security model 👇

github.com/LHMisme420/mcp-authscan

---

## The article

### Your AI agents have a door you forgot to lock. I built the scanner that finds it.

Model Context Protocol is becoming the USB-C of AI — the standard way agents reach your tools, your data, your systems. Adoption is going vertical. The security around it is not.

Here's the uncomfortable part: a huge number of MCP servers are shipping with no authentication at all. No token. No check. Point a client at `/sse` or `/message` or `/mcp` and the server just… answers.

This isn't theoretical. In 2026, security researchers documented an entire family of MCP flaws — unauthenticated config endpoints leading to remote code execution (LiteLLM, CVE-2026-30623), DNS-rebinding that lets a web page reach a local MCP server (the MCP Java SDK, CVE-2026-35568), and the MCP Inspector RCE chain before that (CVE-2025-58444). Different products, same root cause: the front door was never locked.

So I built **mcp-authscan** — an open-source scanner that checks a running MCP server for exactly these failures, in seconds.

**What it actually checks**
- Confirms the target genuinely speaks MCP (a real `initialize` handshake) — then tests `/sse`, `/message`, and `/mcp` for zero-authentication access.
- Catches servers that happily accept a completely fake token.
- Flags CORS that's actually exploitable — with evidence, not a knee-jerk alert on every wildcard.
- Opt-in checks for the RCE preconditions above: unauthenticated config endpoints and missing Host/Origin validation.
- Emits text, JSON, or **SARIF** — so results flow straight into GitHub code scanning and your CI pipeline.

**The hard part wasn't finding problems. It was not crying wolf.**
A lazy scanner flags any `200 OK` as "wide open" — and then lights up on single-page apps, docs sites, and health checks that aren't MCP endpoints at all. Nobody trusts a tool that's wrong half the time. So I tuned it the other way: an HTML page is *not* a finding; an empty, unauthenticated `200` on an MCP path *is*. That precision is the whole game. It's validated by a real test suite — deliberately-broken servers it must flag, hardened servers it must leave alone — running on every commit through lint, type-checks, coverage gates, and dependency audits.

**How you use it**
```
pip install -e .
mcp-authscan scan http://localhost:8000
mcp-authscan scan --targets inventory.txt --format sarif --fail-on high
```
Scan one server, or your entire fleet concurrently. Gate your pipeline so a misconfigured MCP server fails the build instead of reaching production.

**Who needs this**
If you run MCP servers — platform teams, AI product engineers, or security folks auditing your own stack — this is the five-minute check that tells you whether you've left the door open. Find it before someone else does.

**One line I won't compromise on**
Reachability is not permission. mcp-authscan is authorization-first by design: run it against infrastructure you own or are explicitly authorized to test. That's in the README, and it's non-negotiable. Good security tooling respects the line.

It's open source, tested, and CI-gated today. I'd genuinely value your stars, issues, and contributions — and I want to hear what it finds in your environment.

👉 **github.com/LHMisme420/mcp-authscan**

#MCP #AISecurity #AppSec #DevSecOps #OpenSource #ModelContextProtocol #CyberSecurity #AIengineering
