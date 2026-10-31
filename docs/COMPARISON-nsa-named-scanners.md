# Comparison against the scanners named in the NSA AISC MCP guidance

Date: 2026-10-31. Target: http://127.0.0.1:9100/mcp, run locally from tests/fixtures/decoy_auth_server.py.

The May 2026 NSA Artificial Intelligence Security Center CSI (U/OO/6030316-26) names four MCP scanning tools: MCP Scanner, Ramparts, CyberMCP and Proximity. This records each one run against the same target as mcp-authscan, so the results are comparable rather than collected from other people's write-ups.

Versions tested: mcp-authscan 1.1.8 (f282c33), Cisco AI Defense mcp-scanner 4.8.7, Ramparts (version not captured on this run). CyberMCP and Proximity are not yet run.

## Target

decoy_auth_server.py serves protected-resource metadata at /.well-known/oauth-protected-resource/mcp, returns 401 with a WWW-Authenticate challenge on GET and POST /mcp, and accepts POST /token without setting Cache-Control. It is deliberately mild: no tools, no prompts, nothing to poison.

    python3 tests/fixtures/decoy_auth_server.py 9100

## Cisco AI Defense mcp-scanner 4.8.7

    mcp-scanner protocol --server-url http://127.0.0.1:9100/mcp

One finding: HIGH, CWE-319, "MCP server is accessible over unencrypted HTTP", check MCPS-001, threat category Unencrypted Transport. Nothing about the token endpoint.

The target is a loopback address, so plain HTTP over 127.0.0.1 is the normal condition of a local test and reporting it unqualified is noise. Its protocol mode is transport-focused and did not reach the OAuth surface.

## Ramparts

    ./ramparts scan http://127.0.0.1:9100/mcp

AUTHENTICATION ERROR: server requires Bearer authentication (HTTP 401), authorization metadata at http://127.0.0.1:9100/.well-known/oauth-protected-resource/mcp, supply a token with --auth-headers. Assessments executed: None.

Ramparts resolved the metadata pointer correctly and then stopped, requiring a token to be supplied by hand. It assesses the tools, prompts and resources a server exposes, so against a server that refuses unauthenticated calls there is nothing for it to assess. This is a design choice rather than a defect: it assumes the operator already holds credentials.

## mcp-authscan 1.1.8

    mcp-authscan http://127.0.0.1:9100/mcp --authorized-by LHM --auth-basis "own fixture on localhost" --contact <address> --allow-private

5 probes attempted, 4 passed, 1 failed, 4 excluded with prerequisites named, coverage 5 of 5 testable. One LOW finding: OAuth-3 token-cache-control, Cache-Control absent on the token response. Report hash 461fd4d61eee299ff77e60394da0651f465ddd95433368631c16b419e60eed0b, exit contract 2026.10.31.1, exit 0.

The run also reports condition clean alongside that LOW finding. Read together that overstates the result: clean means nothing at or above the fail threshold, not nothing found.

## What it shows

Each tool answers a different question. mcp-scanner's protocol mode covers transport. Ramparts covers the content a server volunteers. mcp-authscan covers the authorization surface and states what it could not reach.

Only one of the three produced a verdict on a server that refuses unauthenticated requests, which is the condition every unreviewed deployment is in.

## What it does not show

Two of four named tools. One target, local, deliberately mild. Ramparts against an open server with poisoned tool descriptions is a different test, and on that target it would likely produce results mcp-authscan cannot, because the content of tools, prompts and resources is invisible to an endpoint prober.

Nothing here establishes that any tool finds fewer or more real vulnerabilities in the field. It establishes what each one assesses.
