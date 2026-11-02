# OWASP MCP Top 10 coverage

Mapping 2026.11.02.1.

Which of the ten categories mcp-authscan can decide on a running MCP server, which it can only partly decide, and which it does not test at all.

A category is covered only when a probe positively demonstrated the property on a live endpoint. A 404, a timeout, a 5xx or an unexpected body is not a pass. A probe that could not run is excluded with its missing prerequisite named, and is counted as neither a pass nor a failure.

Two things no endpoint prober can settle. It cannot verify a three-party OAuth flow, where the client, the authorization server and the resource are separate parties. It reads tool descriptions, prompts and resources, but a read is not a verdict. A clean read demonstrates no property, so tool poisoning and context over-sharing still carry none. It cannot discover a server, only assess one it was handed, so shadow MCP servers are out of reach.

Every report stamps this mapping version beside the probe-set version, so a report issued under one revision is never quietly read as another.

| Category | State | Probes | Backing, or why not |
| --- | --- | --- | --- |
| MCP01 Token Mismanagement & Secret Exposure | covered | OAuth-3, OAuth-4, OAuth-5, OAuth-11 | - |
| MCP02 Privilege Escalation via Scope Creep | partial | OAuth-10 | Only cross-tenant isolation, and only when MCPAUTHSCAN_CROSS_TENANT=1 is set. A default run leaves it untested. |
| MCP03 Tool Poisoning | untested | MCPC-1 | Content is read and directive-like metadata is reported as a finding; a clean read demonstrates no property, so the category carries no verdict. |
| MCP04 Software Supply Chain Attacks & Dependency Tampering | untested | - | Needs package, lockfile and provenance inspection; a running endpoint cannot show it. |
| MCP05 Command Injection & Execution | untested | - | Out of scope by policy. mcp-authscan checks preconditions and does not attempt execution. |
| MCP06 Prompt Injection via Contextual Payloads | untested | - | Needs payload and context analysis rather than an HTTP probe. |
| MCP07 Insufficient Authentication & Authorization | covered | OAuth-1, OAuth-2, OAuth-6, OAuth-7, OAuth-8, OAuth-9, cors, potential_unauthenticated_sensitive_data | - |
| MCP08 Lack of Audit and Telemetry | untested | - | Needs request-level telemetry from the server, which a prober cannot see. |
| MCP09 Shadow MCP Servers | untested | - | Needs network discovery and inventory; a target is supplied, never found. |
| MCP10 Context Injection & Over-Sharing | untested | MCPC-2 | Resource and prompt content is read and private paths are reported as a finding; a clean read demonstrates no property, so the category carries no verdict. |
