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
  2. Write a tiny driver to a temp file and run it with the client under test:
       - ``--client-kind python`` (default): the driver runs under
         ``--client-python`` and resolves ``ClientCredentialsOAuthProvider``
         from fastmcp or the official ``mcp`` SDK.
       - ``--client-kind node``: a ``.mjs`` driver runs under ``--client-node``
         using the TypeScript SDK's ``Client`` + ``StreamableHTTPClientTransport``
         and its ``ClientCredentialsProvider`` if importable.
  3. Observe the decoy, not the child's claims, and report one verdict per
     client:

       FAIL     (exit 1) the decoy captured a POST to ``/token`` carrying an
                         Authorization header: the client sent credentials to an
                         issuer that did not match the protected resource.
       PASS     (exit 0) the client read the protected-resource metadata and
                         presented no credential.
       EXCLUDED (exit 2) neither happened (e.g. the SDK is not installed); the
                         reason names the cause, quoting the child's last stderr
                         line.

The JSON report carries a ``kind`` field ("python" or "node") so rows from
different client stacks are distinguishable.
"""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from mcp_authscan.decoy_auth_server import start_decoy, stop_decoy

# ---------------------------------------------------------------------------
# Python driver. No ``if __name__ == "__main__"`` guard; a function is called
# unconditionally. It must not assume a particular SDK version: it tries each
# known import location for the provider, only passes constructor arguments the
# installed version accepts, and drives through fastmcp's client when fastmcp
# supplied the provider, otherwise through the provider's own auth flow (the
# official ``mcp`` SDK ships no fastmcp and uses httpx2).
# ---------------------------------------------------------------------------
_PY_DRIVER = r'''
import asyncio
import inspect
import sys

_IMPORT_PATHS = (
    "fastmcp.client.auth",
    "fastmcp.client.auth.client_credentials",
    "mcp.client.auth.extensions.client_credentials",
    "mcp.client.auth",
)


def _load_provider():
    last = None
    for path in _IMPORT_PATHS:
        try:
            module = __import__(path, fromlist=["ClientCredentialsOAuthProvider"])
            provider = getattr(module, "ClientCredentialsOAuthProvider", None)
            if provider is not None:
                return provider, path
        except Exception as exc:  # report the last failure, keep trying
            last = "%s: %s" % (path, exc)
    raise ImportError(
        "ClientCredentialsOAuthProvider not found in any known location (%s)" % last
    )


def _make_storage():
    # The official mcp SDK requires a TokenStorage; build an in-memory one that
    # conforms to its protocol. fastmcp's token_storage has a default, so this
    # is never reached on the fastmcp path.
    for path in ("mcp.client.auth", "mcp.client.auth.oauth2"):
        try:
            token_storage = getattr(
                __import__(path, fromlist=["TokenStorage"]), "TokenStorage"
            )
        except Exception:
            continue

        class _MemStore(token_storage):
            def __init__(self):
                self._tokens = None
                self._client = None

            async def get_tokens(self):
                return self._tokens

            async def set_tokens(self, tokens):
                self._tokens = tokens

            async def get_client_info(self):
                return self._client

            async def set_client_info(self, info):
                self._client = info

        return _MemStore()
    return None


def _build(provider_cls, mcp_url, expect_issuer):
    params = inspect.signature(provider_cls.__init__).parameters
    kwargs = {}
    if "client_id" in params:
        kwargs["client_id"] = "probe-client"
    if "client_secret" in params:
        kwargs["client_secret"] = "probe-secret"
    if expect_issuer and "issuer" in params:
        kwargs["issuer"] = expect_issuer
    # Supply a storage only when the provider *requires* one (no default).
    for storage_name in ("storage", "token_storage"):
        param = params.get(storage_name)
        if param is not None and param.default is param.empty:
            storage = _make_storage()
            if storage is not None:
                kwargs[storage_name] = storage
    sys.stderr.write("driver: provider kwargs = %s\n" % sorted(kwargs))
    return provider_cls(mcp_url, **kwargs)


async def _drive_fastmcp(provider, mcp_url):
    # Unchanged fastmcp path: drive through the fastmcp client.
    from fastmcp import Client
    try:
        async with Client(mcp_url, auth=provider) as client:
            await client.list_tools()
    except Exception as exc:
        sys.stderr.write("driver: client raised %s: %s\n" % (type(exc).__name__, exc))


async def _drive_authflow(provider, mcp_url):
    # Official mcp SDK (and any httpx.Auth provider): drive the auth flow
    # directly with whatever HTTP library the SDK bundles.
    try:
        import httpx2 as hx
    except Exception:
        import httpx as hx
    request = hx.Request("GET", mcp_url)
    try:
        flow = provider.async_auth_flow(request)
        outbound = await flow.__anext__()
        async with hx.AsyncClient(timeout=10, follow_redirects=False) as client:
            for _ in range(8):
                response = await client.send(outbound)
                try:
                    outbound = await flow.asend(response)
                except StopAsyncIteration:
                    return
    except Exception as exc:
        sys.stderr.write("driver: client raised %s: %s\n" % (type(exc).__name__, exc))


def main(argv):
    mcp_url = argv[1]
    expect_issuer = argv[2] if len(argv) > 2 and argv[2] else None
    provider_cls, path = _load_provider()
    sys.stderr.write("driver: using %s\n" % path)
    provider = _build(provider_cls, mcp_url, expect_issuer)
    fastmcp_ok = False
    if path.startswith("fastmcp"):
        try:
            import fastmcp  # noqa: F401
            fastmcp_ok = True
        except Exception:
            fastmcp_ok = False
    if fastmcp_ok:
        asyncio.run(_drive_fastmcp(provider, mcp_url))
    else:
        asyncio.run(_drive_authflow(provider, mcp_url))
    sys.stderr.write("driver: auth flow completed\n")


main(sys.argv)
'''

# ---------------------------------------------------------------------------
# Node driver (TypeScript SDK). Static imports of Client/transport; if the SDK
# is not installed these throw at load and node exits non-zero, so the parent
# reports EXCLUDED quoting that error. The auth provider is imported
# dynamically: used if present, otherwise the client runs without auth and the
# decoy simply records that the token endpoint was never exercised.
# ---------------------------------------------------------------------------
_NODE_DRIVER = r'''
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const mcpUrl = process.argv[2];
const expectIssuer = process.argv[3] && process.argv[3].length ? process.argv[3] : null;

function firstLine(e) {
  const m = e && e.message ? String(e.message) : String(e);
  return m.split("\n")[0];
}

let provider = undefined;
try {
  const ext = await import("@modelcontextprotocol/sdk/client/auth-extensions.js");
  if (ext && ext.ClientCredentialsProvider) {
    const opts = { clientId: "probe-client", clientSecret: "probe-secret" };
    if (expectIssuer) opts.expectedIssuer = expectIssuer;
    provider = new ext.ClientCredentialsProvider(opts);
    process.stderr.write(
      "driver: using ClientCredentialsProvider" +
        (expectIssuer ? " (expectedIssuer set)" : "") + "\n"
    );
  } else {
    process.stderr.write(
      "driver: auth-extensions present but no ClientCredentialsProvider; running without auth\n"
    );
  }
} catch (e) {
  process.stderr.write("driver: no auth provider importable (" + firstLine(e) + "); running without auth\n");
}

const transport = new StreamableHTTPClientTransport(
  new URL(mcpUrl),
  provider ? { authProvider: provider } : {}
);
const client = new Client({ name: "mcp-authscan-probe", version: "0" }, { capabilities: {} });
try {
  await client.connect(transport);
  try { await client.listTools(); } catch (e) {}
} catch (e) {
  process.stderr.write("driver: client raised " + (e && e.name ? e.name : "Error") + ": " + firstLine(e) + "\n");
} finally {
  try { await transport.close(); } catch (e) {}
}
process.stderr.write("driver: done\n");
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
    """The cause to quote. Prefer the last line that actually names an error;
    fall back to the last meaningful line, skipping runtime footers such as
    node's trailing ``Node.js v22.x`` so the reason names the cause."""
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    if not lines:
        return ""
    markers = ("Error", "error", "Cannot find", "Traceback", "Exception", "ERR_")
    for line in reversed(lines):
        if any(m in line for m in markers):
            return line
    for line in reversed(lines):
        if not line.startswith("Node.js v"):
            return line
    return lines[-1]


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


def _launch_python(mcp_url, client_python, expect_issuer):
    """Return (completed_process, launch_error)."""
    with tempfile.TemporaryDirectory() as tmp:
        driver_path = Path(tmp) / "issuer_binding_driver.py"
        driver_path.write_text(_PY_DRIVER)
        try:
            child = subprocess.run(
                [client_python, str(driver_path), mcp_url, expect_issuer or ""],
                capture_output=True, text=True, timeout=60,
            )
        except FileNotFoundError:
            return None, "client interpreter not found: %s" % client_python
    return child, None


def _launch_node(mcp_url, client_node, node_cwd, expect_issuer):
    """Return (completed_process, launch_error). The driver is written inside
    node_cwd so a bare ``@modelcontextprotocol/sdk`` import resolves against its
    node_modules."""
    cwd = Path(node_cwd).expanduser()
    if not cwd.is_dir():
        return None, "node project directory not found: %s" % node_cwd
    tmp = tempfile.mkdtemp(dir=str(cwd))
    try:
        driver_path = Path(tmp) / "issuer_binding_driver.mjs"
        driver_path.write_text(_NODE_DRIVER)
        try:
            child = subprocess.run(
                [client_node, str(driver_path), mcp_url, expect_issuer or ""],
                capture_output=True, text=True, timeout=60, cwd=str(cwd),
            )
        except FileNotFoundError:
            return None, "node interpreter not found: %s" % client_node
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return child, None


def run(client_python=None, client_name=None, expect_issuer=None,
        client_kind="python", client_node="node", node_cwd="."):
    server = start_decoy()
    mcp_url = server.base_url + "/mcp"
    child = None
    launch_error = None
    try:
        if client_kind == "node":
            child, launch_error = _launch_node(mcp_url, client_node, node_cwd, expect_issuer)
        else:
            child, launch_error = _launch_python(mcp_url, client_python, expect_issuer)
    except subprocess.TimeoutExpired:
        launch_error = "client under test timed out before a verdict could be observed"

    touches = list(server.touches)
    captured_raw = list(server.captured)
    captured = _evidence(captured_raw)
    token_entry = _token_credential(captured_raw)
    read_metadata = _read_metadata(server.touches)
    stop_decoy(server)

    if token_entry is not None:
        verdict, code = "FAIL", 1
        reason = (
            "client presented an Authorization header to the decoy token "
            "endpoint, whose issuer did not match the protected resource "
            "(authorization: %s)" % redact(token_entry.get("authorization"))
        )
    elif read_metadata and launch_error is None:
        verdict, code = "PASS", 0
        reason = (
            "client read the protected-resource metadata and presented no "
            "credential to the token endpoint"
        )
    else:
        verdict, code = "EXCLUDED", 2
        tail = _last_stderr_line(child.stderr if child else "")
        cause = tail or launch_error or "<empty>"
        reason = (
            "issuer binding was not exercised (no credential reached the token "
            "endpoint and the flow did not complete); child stderr: " + cause
        )

    return _report(client_kind, client_name, verdict, reason, touches, captured, code)


def _report(client_kind, client_name, verdict, reason, touches, captured, code):
    payload = {
        "check": "client-issuer-binding",
        "kind": client_kind,
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
        "--client-kind", choices=["python", "node"], default="python",
        help="client stack under test (default: python)",
    )
    parser.add_argument(
        "--client-python",
        help="interpreter holding the Python client under test (required for --client-kind python)",
    )
    parser.add_argument(
        "--client-node", default="node",
        help="node binary for --client-kind node (default: node)",
    )
    parser.add_argument(
        "--node-cwd", default=".",
        help="directory whose node_modules has @modelcontextprotocol/sdk (default: .)",
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

    if args.client_kind == "python" and not args.client_python:
        parser.error("--client-python is required when --client-kind is python")

    if args.client_name:
        client_name = args.client_name
    elif args.client_kind == "node":
        client_name = "%s (node)" % args.client_node
    else:
        client_name = args.client_python

    return run(
        args.client_python, client_name, args.expect_issuer,
        client_kind=args.client_kind, client_node=args.client_node,
        node_cwd=args.node_cwd,
    )


if __name__ == "__main__":
    sys.exit(main())
