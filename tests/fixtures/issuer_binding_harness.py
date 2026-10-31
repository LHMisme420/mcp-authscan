"""Reproduce client-side OAuth issuer binding (GHSA-vqqp-x5qm-5qp4).

Runs against the decoy authorization server. In vuln mode the provider is given
only credentials, so it discovers the decoy and sends them there. In fixed mode
it is given an issuer that is not the decoy, so it must refuse.
"""
import asyncio
import importlib.util
import sys
import threading
from pathlib import Path

DECOY = Path.home() / 'mcp-authscan/tests/fixtures/decoy_auth_server.py'
PORT = 9100
OTHER_ISSUER = 'http://127.0.0.1:9999'


def load_decoy():
    spec = importlib.util.spec_from_file_location('decoy', str(DECOY))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def attempt(mode):
    from fastmcp import Client
    from fastmcp.client.auth import ClientCredentialsOAuthProvider
    target = 'http://127.0.0.1:%d/mcp' % PORT
    kwargs = {
        'client_id': 'legit-client-id',
        'client_secret': 'legit-client-secret',
        'mcp_url': target,
    }
    if mode == 'fixed':
        kwargs['issuer'] = OTHER_ISSUER
    provider = ClientCredentialsOAuthProvider(**kwargs)
    client = Client(target, auth=provider)
    try:
        async with client:
            await client.list_tools()
    except Exception as exc:
        print('client raised: %s: %s' % (type(exc), str(exc)[:110]))


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'vuln'
    decoy = load_decoy()
    server = decoy.serve(PORT)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        asyncio.run(attempt(mode))
    finally:
        server.shutdown()
    print('MODE ' + mode)
    print('CAPTURED_COUNT %d' % len(decoy.CAPTURE))
    for item in decoy.CAPTURE:
        print('AUTH_HEADER ' + str(item['authorization_header']))
        print('BODY ' + item['body'][:120])


if sys.argv and sys.argv[0].endswith('issuer_binding_harness.py'):
    main()
