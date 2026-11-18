#!/usr/bin/env python3
"""Reconcile a resource-two tool policy and grade its authorization boundary.

The security verdict is NOT graded here. It is produced by the repo's existing
cross-tenant grader, which also carries the tenant-policy handling it reads from the
environment (``MCPAUTHSCAN_TENANT_TOKEN`` / ``MCPAUTHSCAN_FOREIGN_ID``):

    from mcp_authscan.oauth_probes_v2 import probe_cross_tenant

If that import fails the run stops and names the missing module (exit 2). There is
no fallback grader.

``policy.json`` declares resource two, its tools (each ``read`` or ``write``), and
the owning resource. Two reconciliation rules are applied to what the server lists
against what the policy declares:

  * a tool the server lists that the policy does not declare  -> MISMATCH
  * a declared write tool is UNKNOWN unless it was actually requested

The boundary step mints a token for the *other* (owning) resource, presents it to
resource two, and lets ``probe_cross_tenant`` grade whether a foreign-owned record
is refused.

The graded target is an owner-scoped resource server in the shape
``probe_cross_tenant`` is tested against (``tests/fixtures/two_tenant_server.py``),
extended with the MCP ``initialize`` / ``tools/list`` / ``tools/call`` methods and a
``/token`` mint so a token can be minted and presented in one process. (The repo's
fixtures issue opaque, in-process tokens, so the mint side and the resource it is
presented to must share a process; that is a property of the existing fixtures.)
If something is already listening on the target, that server is used instead.

Usage:
    python3 authoritycheck.py policy.json http://127.0.0.1:8412/mcp

Exit: 0 clean; 1 a finding (MISMATCH or boundary FAIL); 2 setup or inconclusive.
"""
import json
import os
import socket
import sys
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

EXIT_CLEAN, EXIT_FINDING, EXIT_SETUP = 0, 1, 2

# Fixture client credential (tests/fixtures/audience_fixture.py).
CLIENT_ID = os.environ.get("FIX_CLIENT_ID", "fixture-client")
CLIENT_SECRET = os.environ.get("FIX_CLIENT_SECRET", "fixture-secret")

# Target behaviour switches (used only when authoritycheck launches its own target).
TARGET_MISBEHAVE = os.environ.get("AUTHSCAN_TARGET_MISBEHAVE") == "1"
TARGET_EXTRA_TOOL = os.environ.get("AUTHSCAN_TARGET_EXTRA_TOOL") == "1"


# --------------------------------------------------------------------------- #
# Graded target: owner-scoped records (two_tenant_server model) + MCP methods. #
# --------------------------------------------------------------------------- #
class _Target(BaseHTTPRequestHandler):
    # Owner labels: the target's own resource owns "rec-home"; the owning resource
    # owns "rec-owner". A token minted for the owning resource must not read
    # "rec-home".
    TOKENS = {}            # opaque token -> owner label
    HOME_RESOURCE = ""     # http://host:port/mcp
    OWNING_RESOURCE = ""   # the policy's owning_resource
    TOOLS = []             # names the server lists
    RECORDS = {"rec-home": "home", "rec-owner": "owner"}

    def log_message(self, *a):
        pass

    def _owner_for(self, resource):
        if resource == self.OWNING_RESOURCE:
            return "owner"
        return "home"

    def _send(self, code, obj=None, extra=None):
        body = b"" if obj is None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _bearer(self):
        h = self.headers.get("Authorization") or ""
        return h[7:].strip() if h.startswith("Bearer ") else ""

    def do_POST(self):
        path = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if path == "/token":
            return self._token(raw)
        if path in ("/mcp", "/", "/initialize"):
            return self._mcp(raw)
        return self._send(404, {"error": "not_found"})

    def _token(self, raw):
        form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True).items()}
        if form.get("client_id") != CLIENT_ID or form.get("client_secret") != CLIENT_SECRET:
            return self._send(400, {"error": "invalid_client"}, {"Cache-Control": "no-store"})
        if form.get("grant_type") != "client_credentials":
            return self._send(400, {"error": "unsupported_grant_type"}, {"Cache-Control": "no-store"})
        resource = form.get("resource") or self.HOME_RESOURCE
        import secrets
        tok = secrets.token_hex(16)
        self.TOKENS[tok] = self._owner_for(resource)
        return self._send(200, {"access_token": tok, "token_type": "Bearer", "expires_in": 3600},
                          {"Cache-Control": "no-store"})

    def _mcp(self, raw):
        tok = self._bearer()
        owner = self.TOKENS.get(tok)
        if owner is None:
            return self._send(401, {"error": "unauthorized"},
                              {"WWW-Authenticate": 'Bearer error="invalid_token"'})
        try:
            msg = json.loads(raw or b"{}")
        except ValueError:
            msg = {}
        mid, method = msg.get("id"), msg.get("method")
        if method == "initialize":
            return self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "authscan-target", "version": "1.0"}}},
                {"Mcp-Session-Id": "authscan-session"})
        if method == "notifications/initialized":
            return self._send(202)
        if method == "tools/list":
            tools = [{"name": name, "inputSchema": {"type": "object", "properties": {}}}
                     for name in self.TOOLS]
            return self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {"tools": tools}})
        if method == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name in ("get_record",):
                rid = args.get("id")
                rec_owner = self.RECORDS.get(rid)
                if rec_owner is None:
                    return self._send(404, {"jsonrpc": "2.0", "id": mid,
                                            "error": {"code": -32004, "message": "no such record"}})
                if rec_owner != owner and not TARGET_MISBEHAVE:
                    return self._send(403, {"jsonrpc": "2.0", "id": mid,
                                            "error": {"code": -32003, "message": "forbidden"}})
                return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                        "result": {"id": rid, "owner": rec_owner}})
            if name in ("list_records",):
                owned = [rid for rid, o in self.RECORDS.items() if o == owner]
                return self._send(200, {"jsonrpc": "2.0", "id": mid, "result": {"records": owned}})
            return self._send(200, {"jsonrpc": "2.0", "id": mid,
                                    "error": {"code": -32601, "message": "tool not found"}})
        return self._send(400, {"jsonrpc": "2.0", "id": mid,
                                "error": {"code": -32601, "message": "method not found"}})


def _listening(host, port):
    try:
        socket.create_connection((host, port), timeout=0.3).close()
        return True
    except OSError:
        return False


def _launch_target(host, port, home_resource, owning_resource, declared_names):
    tools = list(declared_names)
    if TARGET_EXTRA_TOOL:
        tools.append("debug_echo")          # a tool the policy does not declare
    _Target.HOME_RESOURCE = home_resource
    _Target.OWNING_RESOURCE = owning_resource
    _Target.TOOLS = tools
    httpd = ThreadingHTTPServer((host, port), _Target)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    deadline = time.time() + 5
    while time.time() < deadline and not _listening(host, port):
        time.sleep(0.05)
    return httpd


def _mint(token_endpoint, resource, opener):
    import urllib.request
    body = "&".join([
        "grant_type=client_credentials",
        "client_id=%s" % CLIENT_ID,
        "client_secret=%s" % CLIENT_SECRET,
        "resource=%s" % resource,
    ]).encode()
    req = urllib.request.Request(token_endpoint, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with opener.open(req, timeout=5) as r:
        payload = json.loads(r.read())
    tok = payload.get("access_token")
    if not tok:
        raise RuntimeError("authorization side did not issue a token: %s" % payload)
    return tok


def main(argv):
    if len(argv) < 3:
        print("usage: python3 authoritycheck.py policy.json http://host:port/mcp", file=sys.stderr)
        return EXIT_SETUP

    policy_path, target_url = argv[1], argv[2]

    # Existing boundary grading + tenant-policy handling. No fallback: a missing
    # module stops the run and is named.
    try:
        from mcp_authscan.oauth_probes_v2 import probe_cross_tenant
        from mcp_authscan import oauth_probes_v2, monolith, mcp_session
    except ImportError as exc:
        print("[!] missing module: %s" % (getattr(exc, "name", None) or exc), file=sys.stderr)
        return EXIT_SETUP

    # Load the policy.
    try:
        with open(policy_path) as fh:
            policy = json.load(fh)
        declared = {t["name"]: t["access"] for t in policy["tools"]}
        owning_resource = policy["owning_resource"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("[!] could not read policy %s: %s" % (policy_path, exc), file=sys.stderr)
        return EXIT_SETUP

    parsed = urlparse(target_url)
    host, port = parsed.hostname, parsed.port or 80
    base = "%s://%s:%d" % (parsed.scheme, host, port)
    token_endpoint = base + "/token"

    # Reach the target, or stand one up from the shared owner-scoped model.
    launched = None
    if _listening(host, port):
        print("target already listening on %s:%d; using it" % (host, port))
    else:
        launched = _launch_target(host, port, base + "/mcp", owning_resource, declared.keys())
        print("started graded target on %s:%d (owner-scoped, MCP methods)" % (host, port))

    # The grader runs in this process and reaches a private address; authorize it
    # exactly as the cross-tenant test does.
    oauth_probes_v2.ALLOW_PRIVATE_TARGETS = True
    monolith.ALLOWED_HOSTS.add(host.lower())
    opener = __import__("urllib.request", fromlist=["request"]).build_opener()

    try:
        # Authenticate for tools/list with a token for resource two itself.
        home_token = _mint(token_endpoint, base + "/mcp", opener)
        session = mcp_session.open_session(target_url, home_token,
                                           allow_private=True, allowed_hosts={host.lower()})
        if not session.get("established"):
            print("[!] could not open an MCP session: %s" % session.get("reason"), file=sys.stderr)
            return EXIT_SETUP

        status, hdrs, raw = mcp_session._post_jsonrpc(
            target_url, {"jsonrpc": "2.0", "id": 300, "method": "tools/list"},
            home_token, session_id=session.get("session_id"),
            allow_private=True, allowed_hosts={host.lower()})
        listed = []
        msg = mcp_session._parse_body(raw, mcp_session._header(hdrs, "Content-Type"))
        result = msg.get("result") if isinstance(msg, dict) else None
        for tool in (result or {}).get("tools", []):
            if isinstance(tool, dict) and tool.get("name"):
                listed.append(tool["name"])

        # Reconcile listed vs declared.
        grades = {}
        for name in listed:
            access = declared.get(name)
            if access is None:
                grades[name] = "MISMATCH"              # listed, not declared
            elif access == "write":
                grades[name] = "UNKNOWN"               # declared write, not requested here
            else:
                grades[name] = "MATCH"                 # declared read, present
        for name, access in declared.items():
            if name not in listed:
                grades[name] = "ABSENT"                # declared, not listed

        print("")
        print("tool reconciliation (policy %s):" % policy_path)
        for name in sorted(grades):
            note = {"MISMATCH": "listed but policy does not declare it",
                    "UNKNOWN": "declared write; not requested",
                    "MATCH": "declared read; listed",
                    "ABSENT": "declared but not listed"}[grades[name]]
            print("  %-14s %-9s (%s)" % (name, grades[name], note))

        # Boundary grading: mint for the other resource, present it, let the
        # existing cross-tenant grader judge.
        other_token = _mint(token_endpoint, owning_resource, opener)
        os.environ["MCPAUTHSCAN_TENANT_TOKEN"] = other_token
        os.environ["MCPAUTHSCAN_FOREIGN_ID"] = "rec-home"   # owned by resource two
        rec = probe_cross_tenant(target_url, tool="get_record")

        print("")
        print("boundary grading [cross-tenant]: %s%s -- %s" % (
            rec.status,
            " (%s)" % rec.severity if rec.severity else "",
            rec.detail))

        mismatches = [n for n, g in grades.items() if g == "MISMATCH"]
        boundary_fail = rec.status == "FAIL"
        boundary_inconclusive = rec.status in ("NOT_OBSERVED", "EXCLUDED")

        print("")
        if boundary_fail or mismatches:
            parts = []
            if boundary_fail:
                parts.append("boundary FAIL (%s)" % (rec.severity or "finding"))
            if mismatches:
                parts.append("%d MISMATCH (%s)" % (len(mismatches), ", ".join(mismatches)))
            print("VERDICT: FINDING -- " + "; ".join(parts))
            return EXIT_FINDING
        if boundary_inconclusive:
            print("VERDICT: INCONCLUSIVE -- cross-tenant %s (%s)" % (rec.status, rec.limitation or rec.detail))
            return EXIT_SETUP
        print("VERDICT: CLEAN -- boundary held (%s), no undeclared tool" % rec.status)
        return EXIT_CLEAN
    finally:
        if launched is not None:
            launched.shutdown()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
