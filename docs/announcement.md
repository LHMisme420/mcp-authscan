# mcp-authscan — launch announcement

> Link note: the URLs below came from current search results and the writeups
> referenced during development. Verify each resolves before posting — a dead
> link in a launch article costs credibility. On LinkedIn, select the anchor
> text and attach the URL with the editor's link button (pasted Markdown links
> do not render).

## In-feed teaser post (post this; link the article)

Everyone's racing to plug AI agents into everything via MCP.

Almost nobody's checking whether those MCP servers require a password.

I got tired of guessing, so I built an open-source scanner that tells you in seconds — what it checks, how to run it, and why "it's just internal" is not a security model 👇

https://github.com/LHMisme420/mcp-authscan

---

## The article

### Your AI agents have a door you forgot to lock. I built the scanner that finds it.

The Model Context Protocol (MCP) is becoming the USB-C of AI — the standard way agents reach your tools, your data, your systems. Adoption is going vertical. The security around it is not.

Here's the uncomfortable part: a large number of MCP servers are shipping with no authentication at all. No token. No check. Point a client at `/sse`, `/message`, or `/mcp` and the server just… answers.

This isn't theoretical. Over the past year, researchers mapped an entire family of MCP flaws:

- **Unauthenticated config → remote code execution** across LiteLLM, LangChain, and LangFlow — OX Security's supply-chain advisory: https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
- The scale of exposure — reporting on the STDIO design flaw: https://venturebeat.com/security/mcp-stdio-flaw-200000-ai-agent-servers-exposed-ox-security-audit
- The deeper protocol analysis — Cloud Security Alliance research note: https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/
- The earlier MCP Inspector RCE chain (CVE-2025-58444): https://medium.com/@Qubit18/from-xss-to-rce-critical-vulnerability-chain-in-anthropic-mcp-inspector-cve-2025-58444-7092ba4ac442

Different products, same root cause: the front door was never locked.

So I built **mcp-authscan** — an open-source scanner that checks a running MCP server for exactly these failures, in seconds.
➡️ https://github.com/LHMisme420/mcp-authscan

**What it actually checks**
- Confirms the target genuinely speaks MCP (a real `initialize` handshake), then tests `/sse`, `/message`, and `/mcp` for zero-authentication access.
- Catches servers that accept a completely fake token.
- Flags CORS that's actually exploitable — with evidence, not a knee-jerk alert on every wildcard.
- Opt-in checks for the RCE preconditions above: unauthenticated config endpoints and missing Host/Origin validation (the DNS-rebinding class).
- Emits text, JSON, or **SARIF**, so findings drop straight into GitHub code scanning (https://docs.github.com/en/code-security/code-scanning) and your CI.

**The hard part wasn't finding problems. It was not crying wolf.**
A lazy scanner flags any `200 OK` as "wide open" — then lights up on single-page apps, docs sites, and health checks that aren't MCP endpoints at all. Nobody trusts a tool that's wrong half the time. So I tuned it the other way: an HTML page is *not* a finding; an empty, unauthenticated `200` on an MCP path *is*. That precision is the whole game — and it's enforced by a real test suite (deliberately-broken servers it must flag, hardened servers it must leave alone) running on every commit through lint, type-checks, coverage gates, and dependency audits.

**How you use it**
```
git clone https://github.com/LHMisme420/mcp-authscan && cd mcp-authscan
pip install -e .
mcp-authscan scan http://localhost:8000
mcp-authscan scan --targets inventory.txt --format sarif --fail-on high
```
Scan one server, or your entire fleet concurrently. Gate your pipeline so a misconfigured MCP server fails the build instead of reaching production.

Want local targets to try it against safely? Stand up the official reference servers (https://github.com/modelcontextprotocol/servers) on your own machine and scan `localhost`.

**Who needs this**
If you run MCP servers — platform teams, AI product engineers, or security folks auditing your own stack — this is the five-minute check that tells you whether you left the door open. Find it before someone else does.

**One line I won't compromise on**
Reachability is not permission. mcp-authscan is authorization-first by design: run it against infrastructure you own or are explicitly authorized to test. That's the first thing in the README, and it's non-negotiable. Good security tooling respects the line.

It's open source, tested, and CI-gated today. I'd genuinely value your stars, issues, and contributions — and I want to hear what it finds in your environment.

⭐ **https://github.com/LHMisme420/mcp-authscan**

#MCP #AISecurity #AppSec #DevSecOps #OpenSource #ModelContextProtocol #CyberSecurity #AIengineering

---

## Sources / further reading (drop at the end of the article)

- mcp-authscan (the tool): https://github.com/LHMisme420/mcp-authscan
- Model Context Protocol: https://modelcontextprotocol.io
- OX Security — MCP supply-chain RCE advisory: https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
- VentureBeat — MCP STDIO flaw exposure: https://venturebeat.com/security/mcp-stdio-flaw-200000-ai-agent-servers-exposed-ox-security-audit
- Cloud Security Alliance — MCP-by-design RCE note: https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-by-design-rce-ox-security-20260420-csa/
- MCP Inspector CVE-2025-58444 writeup: https://medium.com/@Qubit18/from-xss-to-rce-critical-vulnerability-chain-in-anthropic-mcp-inspector-cve-2025-58444-7092ba4ac442
