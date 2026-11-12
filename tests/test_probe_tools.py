"""--probe-tools: one unauthenticated tools/call after a zero-auth handshake.

In-process stdlib fixtures on 127.0.0.1, ephemeral port. Each fixture records every JSON-RPC
method it receives and the name of every tools/call, so a test can show what was (not) sent.
"""
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

RUNNER = ("import sys; from mcp_authscan.monolith import main; "
          "sys.argv = ['mcp-authscan'] + sys.argv[1:]; main()")
REFUSED_NOTE = "handshake open, tool call refused"


def _tool(name):
    return {"name": name, "description": "fixture", "inputSchema": {"type": "object", "properties": {}}}


class _Fixture:
    def __init__(self, tools, call_mode):
        self.tools = tools
        self.call_mode = call_mode  # execute | jsonrpc_error | http_401 | is_error
        self.methods = []
        self.calls = []
        self.call_auth_headers = []
        fx = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, obj=None):
                body = b"" if obj is None else json.dumps(obj).encode()
                self.send_response(code)
                if code == 401:
                    self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._send(404)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    req = json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    req = {}
                method = req.get("method") if isinstance(req, dict) else None
                rid = req.get("id") if isinstance(req, dict) else None
                fx.methods.append(method)
                if method == "initialize":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                        "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "probe-tools-fixture", "version": "0.0.1"}}})
                if method == "tools/list":
                    return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {"tools": fx.tools}})
                if method == "tools/call":
                    fx.calls.append((req.get("params") or {}).get("name"))
                    fx.call_auth_headers.append(self.headers.get("Authorization"))
                    if fx.call_mode == "execute":
                        return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                            "content": [{"type": "text", "text": "pong"}], "isError": False}})
                    if fx.call_mode == "jsonrpc_error":
                        return self._send(200, {"jsonrpc": "2.0", "id": rid, "error": {
                            "code": -32001, "message": "unauthorized"}})
                    if fx.call_mode == "http_401":
                        return self._send(401)
                    if fx.call_mode == "is_error":
                        return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {
                            "content": [{"type": "text", "text": "unauthorized: tools/call requires a valid bearer token"}],
                            "isError": True}})
                if rid is None:
                    return self._send(202)
                return self._send(200, {"jsonrpc": "2.0", "id": rid, "result": {}})

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/mcp" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def fixture_server():
    made = []

    def make(tools, call_mode="execute"):
        fx = _Fixture(tools, call_mode)
        made.append(fx)
        return fx

    yield make
    for fx in made:
        fx.close()


def _scan(url, tmp_path, *extra, fmt="--json"):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    argv = [url, "--allow-private", fmt, "--contact", "test@example.com", "--authorized-by", "Test",
            "--auth-basis", "local fixture", "--scope", "fixture"] + list(extra)
    out = None
    if fmt == "--json":
        out = tmp_path / "report.json"
        argv += ["--output", str(out)]
    proc = subprocess.run([sys.executable, "-c", RUNNER] + argv, capture_output=True, text=True,
                          timeout=120, env=env)
    data = json.loads(out.read_text()) if out is not None and out.exists() else None
    return proc, data


def _zero_auth(data):
    return [f for f in data["findings"] if f["rule"] == "ZERO-AUTH"]


def _assert_record(rec, outcome, tool, status):
    assert rec["outcome"] == outcome, rec
    assert rec["tool"] == tool
    assert rec["http_status"] == status
    assert rec["version"]
    assert "error" in rec and "content" in rec


def test_executed_call_keeps_zero_auth(tmp_path, fixture_server):
    fx = fixture_server([_tool("delete_user"), _tool("get_status")], "execute")
    proc, data = _scan(fx.url, tmp_path, "--probe-tools")
    assert data is not None, proc.stderr
    assert data["discovery_status"] == "ZERO_AUTH_DETECTED"
    rec = data["tool_call_probe"]
    _assert_record(rec, "EXECUTED", "get_status", 200)
    assert rec["content"] == [{"type": "text", "text": "pong"}]
    assert rec["error"] is None
    assert rec["zero_auth_suppressed"] is False
    hits = _zero_auth(data)
    assert len(hits) == 1
    assert hits[0]["tool_call_probe"]["outcome"] == "EXECUTED"
    assert fx.calls == ["get_status"]
    assert "delete_user" not in fx.calls
    assert fx.call_auth_headers == [None]


def test_refused_jsonrpc_error_in_200_suppresses_zero_auth(tmp_path, fixture_server):
    fx = fixture_server([_tool("probe_ping")], "jsonrpc_error")
    proc, data = _scan(fx.url, tmp_path, "--probe-tools")
    assert data is not None, proc.stderr
    rec = data["tool_call_probe"]
    _assert_record(rec, "REFUSED", "probe_ping", 200)
    assert rec["error"] == {"code": -32001, "message": "unauthorized"}
    assert rec["zero_auth_suppressed"] is True
    assert rec["observation"] == REFUSED_NOTE
    assert _zero_auth(data) == []
    assert fx.calls == ["probe_ping"]


def test_refused_http_401_suppresses_zero_auth(tmp_path, fixture_server):
    fx = fixture_server([_tool("probe_ping")], "http_401")
    proc, data = _scan(fx.url, tmp_path, "--probe-tools")
    assert data is not None, proc.stderr
    rec = data["tool_call_probe"]
    _assert_record(rec, "REFUSED", "probe_ping", 401)
    assert rec["zero_auth_suppressed"] is True
    assert rec["observation"] == REFUSED_NOTE
    assert _zero_auth(data) == []
    assert fx.calls == ["probe_ping"]


def test_refused_is_error_result_suppresses_zero_auth(tmp_path, fixture_server):
    # The h5 enforce-mode shape: HTTP 200, result {content: [...], isError: true}.
    fx = fixture_server([_tool("probe_ping")], "is_error")
    proc, data = _scan(fx.url, tmp_path, "--probe-tools")
    assert data is not None, proc.stderr
    rec = data["tool_call_probe"]
    _assert_record(rec, "REFUSED", "probe_ping", 200)
    assert rec["content"][0]["text"].startswith("unauthorized")
    assert rec["zero_auth_suppressed"] is True
    assert rec["observation"] == REFUSED_NOTE
    assert _zero_auth(data) == []


def test_no_read_only_name_is_not_attempted(tmp_path, fixture_server):
    fx = fixture_server([_tool("delete_user"), _tool("run_job"), _tool("get_or_create"),
                         _tool("settings"), _tool("listing")], "execute")
    proc, data = _scan(fx.url, tmp_path, "--probe-tools")
    assert data is not None, proc.stderr
    rec = data["tool_call_probe"]
    _assert_record(rec, "NOT_ATTEMPTED", None, None)
    assert rec["reason"] == "no read-only tool name matched"
    assert rec["zero_auth_suppressed"] is False
    assert set(rec["tools_skipped_deny"]) == {"delete_user", "run_job", "get_or_create"}
    assert "tools/list" in fx.methods
    assert "tools/call" not in fx.methods
    assert fx.calls == []
    assert len(_zero_auth(data)) == 1


def test_without_flag_no_tools_call_and_no_new_keys(tmp_path, fixture_server):
    fx = fixture_server([_tool("get_status")], "execute")
    proc, data = _scan(fx.url, tmp_path)
    assert data is not None, proc.stderr
    assert "tools/call" not in fx.methods
    assert "tool_call_probe" not in data
    assert all("tool_call_probe" not in f for f in data["findings"])
    assert len(_zero_auth(data)) == 1
    proc_t, _ = _scan(fx.url, tmp_path, fmt="--verbose")
    assert "TOOL-CALL PROBE" not in proc_t.stdout
    assert "Tool-call probe" not in proc_t.stdout + proc_t.stderr
    proc_s, _ = _scan(fx.url, tmp_path, fmt="--sarif")
    assert "toolCallProbe" not in proc_s.stdout
    assert "tools/call" not in fx.methods


def test_text_and_sarif_carry_outcome(tmp_path, fixture_server):
    fx = fixture_server([_tool("probe_ping")], "jsonrpc_error")
    proc_t, _ = _scan(fx.url, tmp_path, "--probe-tools", fmt="--verbose")
    assert "TOOL-CALL PROBE" in proc_t.stdout, proc_t.stderr
    assert "Outcome: REFUSED tool=probe_ping http=200" in proc_t.stdout
    assert "Observation: " + REFUSED_NOTE in proc_t.stdout
    proc_s, _ = _scan(fx.url, tmp_path, "--probe-tools", fmt="--sarif")
    sarif = json.loads(proc_s.stdout)
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["ZERO-AUTH"]["properties"]["toolCallProbe"]["outcome"] == "REFUSED"
    assert all(r["ruleId"] != "ZERO-AUTH" for r in sarif["runs"][0]["results"])


def test_tokenizer_and_selection():
    from mcp_authscan.monolith import select_probe_tool, tool_name_words
    assert tool_name_words("getHTTPStatus") == ["get", "http", "status"]
    assert tool_name_words("files.read/v2-info now") == ["files", "read", "v2", "info", "now"]
    assert select_probe_tool([{"name": "settings"}, {"name": "listing"}])[0] is None
    assert select_probe_tool([{"name": "getOrCreate"}, {"name": "healthCheck"}]) == ("healthCheck", ["getOrCreate"])
    assert select_probe_tool([{"name": "admin_list"}, {"name": "ping"}]) == ("ping", ["admin_list"])
