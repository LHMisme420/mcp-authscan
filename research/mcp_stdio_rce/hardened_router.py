#!/usr/bin/env python3
"""LOCAL research mock -- the hardened counterpart to vulnerable_router.py.

Shows the two mitigations that close the OX Security "config -> command"
class at the router layer:

  1. Authentication on BOTH the registry listing and the registration endpoint
     (unauthenticated requests get 401).
  2. A launcher allowlist + argument sanity checks on registration, so a
     registered command cannot be arbitrary (disallowed -> 403). This mock does
     not actually spawn anything; the point is the validation gate.

Note: the deeper design issue is that STDIO executes at spawn time regardless
of front-door controls, so the durable fix is to not expose config->spawn to
untrusted input at all. This mock demonstrates the router-layer controls that
make the documented product RCEs non-trivial.

Run:  ROUTER_TOKEN=secret python3 hardened_router.py --port 9202
"""
import argparse
import json
import os
import shlex
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOKEN = os.environ.get("ROUTER_TOKEN", "change-me")
# Only known MCP launchers may be registered; the basename must match exactly.
ALLOWED_LAUNCHERS = {"npx", "uvx", "python", "python3", "node"}
SHELL_METACHARS = set(";|&`$><\n")


class HardenedRouter(BaseHTTPRequestHandler):
    registry = {}

    def log_message(self, *args):
        pass

    def _json(self, code, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _authed(self):
        return self.headers.get("Authorization", "") == f"Bearer {TOKEN}"

    def _validate(self, command):
        cmd = command if isinstance(command, list) else shlex.split(command)
        if not cmd:
            return None, "empty command"
        launcher = os.path.basename(cmd[0])
        if launcher not in ALLOWED_LAUNCHERS:
            return None, f"launcher {launcher!r} not in allowlist"
        if any(ch in part for part in cmd for ch in SHELL_METACHARS):
            return None, "shell metacharacters rejected"
        return cmd, None

    def do_GET(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"},
                              {"WWW-Authenticate": "Bearer"})
        if self.path.split("?", 1)[0] in ("/mcp/servers", "/config/mcp"):
            return self._json(200, {"servers": self.registry})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._json(401, {"error": "unauthorized"},
                              {"WWW-Authenticate": "Bearer"})
        length = int(self.headers.get("Content-Length") or 0)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": "invalid json"})
        name, command = data.get("name"), data.get("command")
        if not name or not command:
            return self._json(400, {"error": "name and command required"})
        cmd, error = self._validate(command)
        if error:
            return self._json(403, {"error": error})
        # Validated; a real router would spawn a vetted launcher here. The mock
        # records intent only -- it never executes arbitrary input.
        self.registry[name] = cmd
        return self._json(200, {"registered": name, "spawned": False})

    do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description="LOCAL hardened MCP-config mock (loopback only)")
    parser.add_argument("--port", type=int, default=9202)
    args = parser.parse_args()
    print(f"[hardened-router] LOCAL ONLY on http://127.0.0.1:{args.port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), HardenedRouter).serve_forever()


if __name__ == "__main__":
    main()
