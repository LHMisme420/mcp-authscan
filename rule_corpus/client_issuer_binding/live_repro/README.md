# Live repro - rogue-AS credential redirection (C-series)

Proves what the C1/C2 static findings cost at runtime: an MCP OAuth client
using an M2M provider without issuer= sends its credentials to whichever
authorization server the MCP server advertises (RFC 9728 protected-resource
metadata). Vuln class GHSA-qx49-fqc8-xw99 / MCP SEP-2352.

rogue_as_repro.py stands up a rogue MCP server + rogue AS on loopback, points
the real mcp SDK provider at them, and records what reaches the attacker's
token endpoint. Each of the three M2M shapes runs twice - unbound (no issuer=)
and bound (issuer= the legitimate AS):

- client_secret_basic: unbound leaks secret in the Basic header; bound refuses
- client_secret_post: unbound leaks secret in the form body; bound refuses
- private_key_jwt: unbound leaks a signed assertion audienced to the attacker
  (replayable at the real AS); bound refuses

Run:
    pip install mcp
    python3 rogue_as_repro.py          # human-readable
    python3 rogue_as_repro.py --json   # JSON + report_sha256 to anchor

--json emits a report_sha256 over the full result (both runs, all shapes, the
captured token-endpoint bodies, and the SDK version under test) so the repro can
be anchored to Ethereum alongside the finding. Re-run it against the exact mcp
version you cite; the captured version is in the report.

The bound run's refusal is logged by the SDK as an OAuthFlowError ("authorization
server metadata issuer mismatch") - that is the guard firing before the token
request is built, not a harness error.
