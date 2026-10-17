#!/usr/bin/env python3
"""LOCAL research mock -- the "unauthenticated config -> command spawn" antipattern.

This is a minimal, self-contained reproduction of the *class* of flaw OX
Security documented across LiteLLM / LangChain / LangFlow (an unauthenticated
MCP-configuration interface that spawns a STDIO process straight from config,
with no validation). It is deliberately tiny and is NOT a real product.

Purpose: study and detect the pattern on your OWN machine. It is not a tool for
attacking anything, and it only ever spawns the command YOU hand it locally.
See README.md. Bind address is forced to loopback.

Run:  python3 vulnerable_router.py --port 9201
"""
import argparse
import json
import shlex
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class VulnerableRouter(BaseHTTPRequestHandler):
    registry = {}  # name -> command (class-level, like a shared config store)

    def log_message(self, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def do_GET(self):
        # FLAW #1: the MCP server registry is listed without any authentication.
        if self.path.split("?", 1)[0] in ("/mcp/servers", "/config/mcp"):
            return self._json(200, {"servers": self.registry})
        return self._json(404, {"error": "not found"})

    def do_POST(self):
        # FLAW #2: unauthenticated registration spawns the command AT REGISTER
        # TIME, with no validation -- execution happens at process-spawn, not at
        # request time, so a front-door auth proxy would not even see it.
        length = int(self.headers.get("Content-Length") or 0)
        try:
            data = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": "invalid json"})
        name, command = data.get("name"), data.get("command")
        if not name or not command:
            return self._json(400, {"error": "name and command required"})
        cmd = command if isinstance(command, list) else shlex.split(command)
        try:
            # No auth check, no allowlist: arbitrary local command execution.
            subprocess.Popen(cmd)
        except Exception as exc:  # noqa: BLE001 - surface spawn failure to caller
            return self._json(500, {"error": str(exc)})
        self.registry[name] = cmd
        return self._json(200, {"registered": name, "spawned": True})

    do_HEAD = do_GET


def main():
    parser = argparse.ArgumentParser(description="LOCAL vulnerable MCP-config mock (loopback only)")
    parser.add_argument("--port", type=int, default=9201)
    args = parser.parse_args()
    print(f"[vulnerable-router] LOCAL ONLY on http://127.0.0.1:{args.port}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), VulnerableRouter).serve_forever()


if __name__ == "__main__":
    main()
