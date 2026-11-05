"""Client-side OAuth issuer-binding check for MCP clients.

This is NOT a server scanner and is never invoked from a normal scan. It tests
one thing about an MCP *client*: when a protected resource points at an
authorization server whose issuer does not match what the client was told to
expect, does the client still hand over its credentials?

How it works:

  1. Start a local decoy authorization server (the single implementation in
     ``mcp_authscan.decoy_auth_server``). The decoy advertises its own base URL
     as both the protected resource's authorization server and that server's
     issuer, and answers ``/mcp`` with 401 + ``WWW-Authenticate`` so client
     discovery actually starts.
  2. Write a tiny driver to a temp file and run it with ``--client-python``, the
     interpreter that holds the client library under test. The driver imports
     ``ClientCredentialsOAuthProvider`` and drives its auth flow against the
     decoy's ``/mcp`` URL.
  3. Observe the decoy, not the child's claims, and report one verdict:

       FAIL     (exit 1) the decoy captured a POST to ``/token`` carrying an
                         Authorization header: the client sent credentials to an
                         issuer that did not match the protected resource.
       PASS     (exit 0) the client read the protected-resource metadata and
                         presented no credential.
       EXCLUDED (exit 2) neither happened; the reason names the cause by quoting
                         the last line of the child's stderr.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp_authscan.decoy_auth_server import start_decoy, stop_decoy

# The driver run inside --client-python. It must not assume any particular
# fastmcp/mcp version: it tries each known import location for the provider and
# only passes constructor arguments the installed version actually accepts.
# There is deliberately no ``if __name__ == "__main__"`` guard; the driver is
# driven through a function that is called unconditionally at import/run time.
_DRIVER = r'''
import asyncio
import inspect
import sys

_IMPORT_PATHS = (
    "fastmcp.client.auth",
    "fastmcp.client.auth.client_credentials",
    "mcp.client.auth.extensions.client_credentials",
)


def _load_provider():
    last = None
    for path in _IMPORT_PATHS:
        try:
            module = __import__(path, fromlist=["ClientCredentialsOAuthProvider"])
            return getattr(module, "ClientCredentialsOAuthProvider")
        except Exception as exc:  # report the last failure, keep trying
            last = "%s: %s" % (path, exc)
    raise ImportError(
        "ClientCredentialsOAuthProvider not found in any known location (%s)" % last
    )


def _build(provider_cls, mcp_url, expect_issuer):
    params = inspect.signature(provider_cls.__init__).parameters
    kwargs = {}
    if "client_id" in params:
        kwargs["client_id"] = "probe-client"
    if "client_secret" in params:
        kwargs["client_secret"] = "probe-secret"
    if expect_issuer and "issuer" in params:
        kwargs["issuer"] = expect_issuer
    sys.stderr.write("driver: provider kwargs = %s\n" % sorted(kwargs))
    return provider_cls(mcp_url, **kwargs)


async def _drive(provider, mcp_url):
    # Drive through the client's own stack (whatever HTTP library the installed
    # version bundles): one MCP request -> 401 -> discovery -> (maybe) token
    # request -> retry. The decoy, not the client, decides the verdict, so a
    # failing handshake after the token call is expected and swallowed here.
    from fastmcp import Client
    try:
        async with Client(mcp_url, auth=provider) as client:
            await client.list_tools()
    except Exception as exc:
        sys.stderr.write("driver: client raised %s: %s\n" % (type(exc).__name__, exc))


def main(argv):
    mcp_url = argv[1]
    expect_issuer = argv[2] if len(argv) > 2 and argv[2] else None
    provider_cls = _load_provider()
    sys.stderr.write("driver: using %s\n" % provider_cls.__module__)
    provider = _build(provider_cls, mcp_url, expect_issuer)
    asyncio.run(_drive(provider, mcp_url))
    sys.stderr.write("driver: auth flow completed\n")


main(sys.argv)
'''

_TOKEN_PATH = "/token"
_RESOURCE_METADATA_MARKER = "oauth-protected-resource"


def redact(value):
    """First five and last four characters; never the raw value."""
    if not value:
        return value
    text = str(value)
    if len(text) <= 9:
        return "*" * len(text)
    return text[:5] + "..." + text[-4:]


def _last_stderr_line(stderr):
    for line in reversed((stderr or "").splitlines()):
        if line.strip():
            return line.strip()
    return ""


def _token_credential(captured):
    """Return the capture dict for a /token POST carrying an Authorization
    header, or None. That header is the credential leak this check looks for."""
    for entry in captured:
        path = (entry.get("path") or "").split("?")[0]
        if path == _TOKEN_PATH and entry.get("authorization"):
            return entry
    return None


def _read_metadata(touches):
    return any(_RESOURCE_METADATA_MARKER in touch for touch in (touches or []))


def _evidence(captured):
    rows = []
    for entry in captured:
        rows.append({
            "path": entry.get("path"),
            "authorization": redact(entry.get("authorization")),
            "body_keys": sorted((entry.get("body") or {}).keys()),
        })
    return rows


def run(client_python, client_name, expect_issuer):
    server = start_decoy()
    mcp_url = server.base_url + "/mcp"
    child = None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            driver_path = Path(tmp) / "issuer_binding_driver.py"
            driver_path.write_text(_DRIVER)
            child = subprocess.run(
                [client_python, str(driver_path), mcp_url, expect_issuer or ""],
                capture_output=True,
                text=True,
                timeout=60,
            )
    except FileNotFoundError:
        stop_decoy(server)
        return _report(
            client_name, "EXCLUDED",
            "client interpreter not found: %s" % client_python,
            [], [], 2,
        )
    except subprocess.TimeoutExpired:
        stop_decoy(server)
        return _report(
            client_name, "EXCLUDED",
            "client under test timed out before a verdict could be observed",
            list(server.touches), _evidence(server.captured), 2,
        )

    touches = list(server.touches)
    captured = _evidence(server.captured)
    token_entry = _token_credential(server.captured)
    read_metadata = _read_metadata(server.touches)
    stop_decoy(server)

    if token_entry is not None:
        verdict, code = "FAIL", 1
        reason = (
            "client presented an Authorization header to the decoy token "
            "endpoint, whose issuer did not match the protected resource "
            "(authorization: %s)" % redact(token_entry.get("authorization"))
        )
    elif read_metadata:
        verdict, code = "PASS", 0
        reason = (
            "client read the protected-resource metadata and presented no "
            "credential to the token endpoint"
        )
    else:
        verdict, code = "EXCLUDED", 2
        tail = _last_stderr_line(child.stderr if child else "")
        reason = (
            "issuer binding was not exercised (client never read the "
            "protected-resource metadata); child stderr: "
            + (tail or "<empty>")
        )

    return _report(client_name, verdict, reason, touches, captured, code)


def _report(client_name, verdict, reason, touches, captured, code):
    payload = {
        "check": "client-issuer-binding",
        "client": client_name,
        "verdict": verdict,
        "reason": reason,
        "touches": touches,
        "captured": captured,
    }
    print(json.dumps(payload, indent=2))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="python -m mcp_authscan.client_check",
        description="Test an MCP client's OAuth issuer binding from the client side.",
    )
    parser.add_argument(
        "--client-python", required=True,
        help="interpreter holding the client library under test",
    )
    parser.add_argument(
        "--client-name", default=None,
        help="optional label for the report",
    )
    parser.add_argument(
        "--expect-issuer", default=None,
        help="the issuer the client should be configured to expect",
    )
    args = parser.parse_args(argv)
    client_name = args.client_name or args.client_python
    return run(args.client_python, client_name, args.expect_issuer)


if __name__ == "__main__":
    sys.exit(main())
