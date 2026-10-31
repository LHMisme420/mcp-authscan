# Issuer binding harness

Decoy authorization server and client harness for GHSA-vqqp-x5qm-5qp4, fixed in fastmcp 4.1.2. A test harness, not a scanner probe: it lives in tests/fixtures and is never imported by the scanner.

## What it demonstrates

The MCP server chooses which authorization server receives the client's credentials. In 4.1.1 a client with no issuer configured sends its credentials to whatever the server advertises. In 4.1.2 the same client with issuer set refuses before any credential leaves.

## Fixtures

- tests/fixtures/decoy_auth_server.py: stdlib only. Serves protected-resource and authorization-server metadata, returns a 401 challenge with resource_metadata on GET and POST /mcp, records every POST to /token.
- tests/fixtures/issuer_binding_harness.py: runs the client in vuln or fixed mode and prints the capture count.

## Runs, 2026-10-31

vuln mode, fastmcp 4.1.1, /tmp/v411:

    decoy listening on 9100
    MCPDeprecationWarning: Omitting issuer is deprecated ... Without it, the MCP server decides which authorization server receives this client's credentials
    CAPTURED grant_type=client_credentials&resource=http%3A%2F%2F127.0.0.1%3A9100%2Fmcp
    OAuthTokenError: Token exchange failed (400): invalid_client
    MODE vuln
    CAPTURED_COUNT 1
    AUTH_HEADER Basic bGVnaXQtY2xpZW50LWlkOmxlZ2l0LWNsaWVudC1zZWNyZXQ=
    BODY grant_type=client_credentials&resource=http%3A%2F%2F127.0.0.1%3A9100%2Fmcp

That Basic value decodes to a test client id and secret created only for this harness. No real credential is in it.

fixed mode, fastmcp 4.1.2, /tmp/v412:

    decoy listening on 9100
    OAuthFlowError: No authorization server metadata discovered for configured issuer http://127.0.0.1:9999
    MODE fixed
    CAPTURED_COUNT 0

## Reading it

The 400 in vuln mode is the decoy refusing the grant, not the vulnerability failing. The capture is the finding: the client authenticated to a server that was never its authorization server.

In fixed mode the error is the fix working. 4.1.2 requires metadata discovered for the configured issuer before it exchanges anything, so pointed at an unbound port it sent nothing.

## Limits

Client-side behaviour only. It does not scan a live server, and a server-side scan cannot find this class, because there is nothing on the server to compare the issuer against.

## Reproduce

    python3 -m venv /tmp/v411
    /tmp/v411/bin/pip install -q fastmcp==4.1.1
    python3 -m venv /tmp/v412
    /tmp/v412/bin/pip install -q fastmcp==4.1.2
    /tmp/v411/bin/python tests/fixtures/issuer_binding_harness.py vuln
    /tmp/v412/bin/python tests/fixtures/issuer_binding_harness.py fixed
