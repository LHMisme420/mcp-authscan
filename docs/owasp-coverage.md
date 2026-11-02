# OWASP MCP Top 10 coverage

Mapping 2026.11.02.1.
A category is covered only when a probe positively demonstrated it.

| Category | State | Probes | Backing, or why not |
| --- | --- | --- | --- |
| MCP01 Token Mismanagement & Secret Exposure | covered | OAuth-3, OAuth-4, OAuth-5, OAuth-11 | - |
| MCP02 Privilege Escalation via Scope Creep | partial | OAuth-10 | Only cross-tenant isolation, and only when MCPAUTHSCAN_CROSS_TENANT=1 is set. A default run leaves it untested. |
| MCP03 Tool Poisoning | untested | - | Needs the tool description content read and compared; mcp-authscan does not read tools, prompts or resources. |
| MCP04 Software Supply Chain Attacks & Dependency Tampering | untested | - | Needs package, lockfile and provenance inspection; a running endpoint cannot show it. |
| MCP05 Command Injection & Execution | untested | - | Out of scope by policy. mcp-authscan checks preconditions and does not attempt execution. |
| MCP06 Prompt Injection via Contextual Payloads | untested | - | Needs payload and context analysis rather than an HTTP probe. |
| MCP07 Insufficient Authentication & Authorization | covered | OAuth-1, OAuth-2, OAuth-6, OAuth-7, OAuth-8, OAuth-9, cors, potential_unauthenticated_sensitive_data | - |
| MCP08 Lack of Audit and Telemetry | untested | - | Needs request-level telemetry from the server, which a prober cannot see. |
| MCP09 Shadow MCP Servers | untested | - | Needs network discovery and inventory; a target is supplied, never found. |
| MCP10 Context Injection & Over-Sharing | untested | - | Needs resource and prompt content read and compared for over-sharing. |
