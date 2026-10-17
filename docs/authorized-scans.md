# Scan explicitly authorized HTTP endpoints

This replaces the uploaded registry-enumeration script. It does not enumerate
public servers, modify findings databases, or upload reports to VATA.
The existing website scanner and deployment are unchanged.

Run from the project root, replacing the example with an endpoint you own or
have explicit permission to test:

```sh
python3 -m mcp_authscan.authorized_scan \
  --authorized \
  --target https://your-server.example/tools/list \
  --output /tmp/vata-authorized-report.json
```

Supply `--target` again for another authorized endpoint (up to 100).
Each URL is tested exactly as supplied: no automatic endpoint discovery,
registry requests, or redirects. Credentials, query strings, and fragments
are rejected. All targets are validated before requests start. An existing
output file is never overwritten. Without `--output`, JSON goes to stdout.

For a JSON-RPC endpoint that uses POST:

```sh
python3 -m mcp_authscan.authorized_scan --authorized \
  --target https://your-server.example/mcp --method POST
```

POST sends **only `tools/list`**. No tools are invoked, no credentials are sent,
and cookies received from the server are never reused. Two anonymous Origin
probes are made per endpoint. `--authorized` is your confirmation of permission,
not a technical proof of ownership.

## Interpreting results

- A `200` response, tool listing, or wildcard CORS header alone is **not** a finding.
- `401` and `403` are protected responses, not vulnerabilities.
- Sensitive-data patterns in a successful anonymous response produce a
  **potential exposure for manual review**, not a confirmed critical finding.
  Public/synthetic records can trigger heuristics.
- CORS uses VATA's shared evidence-based policy: arbitrary-Origin reflection
  needs successful anonymous sensitive-data evidence from both probes;
  wildcard findings additionally need cookie-auth/credential context.
- Redirects, errors, oversized bodies, encoded bodies, and SSE bodies are marked incomplete,
  not silently reported as safe. This is a limited HTTP probe, not a complete
  MCP session/authentication assessment.
- Response bodies, cookie values, and raw headers are not saved in the report.
  URLs and diagnostic metadata remain in the report; keep it private.

Responses are sampled up to 64 KiB; SSE bodies are not consumed.
`--timeout` accepts 1–30 seconds (default 5) for socket operations and a checked
body-read deadline. A blocking read can take up to one extra socket timeout.
Requests are sequential, with no retries or authenticated follow-up.

Exit status: **0** = completed without findings, **1** = findings needing review,
**2** = invalid input or any incomplete scan. No findings is not proof of security.

Tests use only local synthetic servers:

```sh
python3 -m unittest discover -s tests -p 'test_authorized_scan.py' -v
```
