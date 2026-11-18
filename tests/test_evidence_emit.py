"""Scanner -> security-state-v1 / observation-v1 emission.

Unit tests drive evidence_emit with graded payloads shaped like monolith's
canonical_payload; end-to-end tests run the real CLI against a loopback fixture.
"""
import glob
import hashlib
import json
import os
import subprocess
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from mcp_authscan import evidence_emit
from mcp_authscan.evidence.observation import null_fields, verify_observation
from mcp_authscan.evidence.state import canonical_json, compute_state_id

ROOT = Path(__file__).resolve().parents[1]
TARGET = "http://127.0.0.1:9999/mcp"


def _probe(pid, name, status, **kw):
    rec = {"probe_id": pid, "name": name, "status": status, "headers_observed": {},
           "limitation": None, "detail": None, "prerequisites": [], "endpoint": TARGET}
    rec.update(kw)
    return rec


def _payload(probes, tools=None, reasons=()):
    counts = {k: sum(1 for p in probes if p["status"] == k)
              for k in ("PASS", "FAIL", "NOT_OBSERVED", "EXCLUDED", "NOT_IMPLEMENTED")}
    inspected = {} if tools is None else {"tools": tools}
    return {
        "target": TARGET, "probes": probes, "counts": counts,
        "content_observed": {"version": "x", "inspected": inspected, "reasons": list(reasons)},
        "run_started_at": "2026-11-18T20:00:00+00:00", "probe_set_version": "2026.11.16.1",
        "not_implemented": [], "report_hash": "ab" * 32,
    }


CORS = (13, "cross-origin read on the MCP endpoint")
AUD = (11, "token-audience")


@pytest.mark.parametrize("headers, wildcard, creds", [
    ({"access-control-allow-origin": "*"}, True, False),
    ({"access-control-allow-origin": "https://probe.invalid", "access-control-allow-credentials": "true"}, True, True),
    ({"access-control-allow-origin": "https://app.example.com"}, False, False),
    ({}, False, False),
])
def test_cors_from_conclusive_record(headers, wildcard, creds):
    status = "FAIL" if wildcard else "PASS"
    state, _ = evidence_emit.build_state(_payload([_probe(*CORS, status, headers_observed=headers)]), False)
    assert state["cors"] == {"allow_origin_wildcard": wildcard, "allow_credentials": creds, "allowed_origins": None}


@pytest.mark.parametrize("status", ["NOT_OBSERVED", "EXCLUDED"])
def test_cors_inconclusive_is_null_with_reason(status):
    state, unest = evidence_emit.build_state(
        _payload([_probe(*CORS, status, limitation="HTTP 405")]), False)
    assert state["cors"]["allow_origin_wildcard"] is None
    reason = {e["field"]: e["reason"] for e in unest}["cors.allow_origin_wildcard"]
    assert status in reason and "HTTP 405" in reason


def test_duplicate_probe_id_13_disambiguated_by_name():
    probes = [_probe(13, "denial-shape", "FAIL"),
              _probe(*CORS, "PASS", headers_observed={})]
    state, _ = evidence_emit.build_state(_payload(probes), False)
    assert state["cors"]["allow_origin_wildcard"] is False


@pytest.mark.parametrize("status, endpoint, expected", [
    ("FAIL", TARGET, False),
    ("PASS", TARGET, True),
    ("PASS", "http://127.0.0.1:9999/token", None),   # AS refused to mint: endpoint not exercised
    ("EXCLUDED", None, None),
    ("NOT_OBSERVED", TARGET, None),
])
def test_audience_enforced(status, endpoint, expected):
    state, unest = evidence_emit.build_state(_payload([_probe(*AUD, status, endpoint=endpoint)]), False)
    assert state["audience"]["enforced"] is expected
    assert ("audience.enforced" in null_fields(state)) == (expected is None)


@pytest.mark.parametrize("credentialed, tools, unauth, auth", [
    (False, 0, [], None),
    (False, 3, None, None),      # count only: names are not in the graded result
    (False, None, None, None),
    (True, 0, None, []),
    (True, 2, None, None),
])
def test_tool_visibility(credentialed, tools, unauth, auth):
    state, _ = evidence_emit.build_state(_payload([], tools=tools), credentialed)
    assert state["tool_visibility"] == {"unauthenticated_tools": unauth, "authenticated_tools": auth}


def test_origin_always_null_no_probe():
    state, unest = evidence_emit.build_state(_payload([]), False)
    assert state["origin"] == {"validated": None, "allowed_origins": None}
    assert "Origin" in {e["field"]: e["reason"] for e in unest}["origin.validated"]


def test_unestablished_covers_exactly_the_null_fields():
    probes = [_probe(*CORS, "PASS"), _probe(*AUD, "FAIL")]
    state, unest = evidence_emit.build_state(_payload(probes, tools=0), False)
    assert [e["field"] for e in unest] == null_fields(state)


def test_observation_verifies_and_is_outside_state_id():
    probes = [_probe(*CORS, "PASS"), _probe(*AUD, "EXCLUDED", limitation="No client credential supplied"),
              _probe(5, "jwks-keys", "NOT_OBSERVED", detail="HTTP 502")]
    payload = _payload(probes, tools=0)
    state, unest = evidence_emit.build_state(payload, False)
    end = datetime(2026, 11, 18, 20, 0, 5, tzinfo=UTC)
    obs = evidence_emit.build_observation(state, unest, payload, scanner_version="9.9.9", ended_at=end)
    verify_observation(obs)
    assert obs["state_id"] == compute_state_id(state)
    assert obs["coverage"] == {"in_scope": 2, "pass": 1, "fail": 0, "not_observed": 1, "excluded": 1}
    assert obs["not_observed"] == [{"probe_id": "5:jwks-keys", "reason": "HTTP 502", "affects": []}]
    assert obs["excluded"][0]["affects"] == ["audience.enforced"]
    assert obs["observed_at"] == {"start": "2026-11-18T20:00:00Z", "end": "2026-11-18T20:00:05Z"}
    # Different observation, same boundary: same STATE ID.
    later = evidence_emit.build_observation(state, unest, dict(payload, report_hash="cd" * 32),
                                            scanner_version="10.0.0", ended_at=end)
    assert later["state_id"] == obs["state_id"]


def test_observation_refuses_count_mismatch():
    payload = _payload([_probe(5, "jwks-keys", "NOT_OBSERVED")])
    payload["counts"]["NOT_OBSERVED"] = 2
    state, unest = evidence_emit.build_state(payload, False)
    with pytest.raises(ValueError):
        evidence_emit.build_observation(state, unest, payload, scanner_version="x")


@pytest.mark.parametrize("tamper", [
    lambda o: o.update(state_id="0" * 64),
    lambda o: o["coverage"].update(in_scope=99),
    lambda o: o["unestablished"].pop(),
    lambda o: o["observed_at"].update(end="2000-01-01T00:00:00Z"),
])
def test_verify_observation_rejects_tampering(tamper):
    payload = _payload([_probe(*CORS, "PASS")], tools=0)
    state, unest = evidence_emit.build_state(payload, False)
    obs = evidence_emit.build_observation(state, unest, payload, scanner_version="x")
    tamper(obs)
    with pytest.raises(ValueError):
        verify_observation(obs)


def test_evidence_dir_precedence(tmp_path):
    assert evidence_emit.evidence_dir("/x/ev", str(tmp_path / "r.json")) == "/x/ev"
    assert evidence_emit.evidence_dir(None, str(tmp_path / "r.json")) == str(tmp_path)
    assert evidence_emit.evidence_dir(None, None) == os.path.join(os.getcwd(), "mcp-authscan-evidence")


# ---- end to end: the real CLI ------------------------------------------------

def _zero_auth_handler(acao):
    class H(BaseHTTPRequestHandler):
        def _send(self, obj, code=200):
            body = b"" if obj is None else json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if acao:
                self.send_header("Access-Control-Allow-Origin", acao)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            try:
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            except ValueError:
                msg = {}
            m, mid = msg.get("method"), msg.get("id")
            if m == "initialize":
                self._send({"jsonrpc": "2.0", "id": mid, "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "zf", "version": "0"}, "instructions": "x" * 900}})
            elif m in ("tools/list", "prompts/list", "resources/list"):
                self._send({"jsonrpc": "2.0", "id": mid, "result": {m.split("/")[0]: []}})
            elif mid is None:
                self._send(None, 202)
            else:
                self._send({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "nf"}})

        def do_GET(self):
            self._send({"error": "nf"}, 404)

        def log_message(self, *a):
            pass
    return H


@pytest.fixture
def zero_auth_cors():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _zero_auth_handler("*"))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}/mcp"
    finally:
        srv.shutdown()
        srv.server_close()


AUTH = ["--allow-private", "--contact", "t@example.test", "--authorized-by", "T", "--auth-basis", "local fixture"]


def _run(args, cwd):
    env = dict(os.environ)
    env.pop("MCPAUTHSCAN_TOKEN", None)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), *args], cwd=cwd,
                          capture_output=True, text=True, timeout=120, env=env)


def test_cli_emits_state_and_observation(tmp_path, zero_auth_cors):
    ev = tmp_path / "ev"
    proc = _run([zero_auth_cors, "--json", "--evidence-dir", str(ev), *AUTH], cwd=tmp_path)
    assert proc.returncode == 1, proc.stderr          # CORS wildcard + credentials: CRITICAL finding
    report = json.loads(proc.stdout)                  # stdout is still exactly the JSON report
    [state_file] = glob.glob(str(ev / "*.state.json"))
    [obs_file] = glob.glob(str(ev / "observation-*.json"))
    state = json.loads(Path(state_file).read_text())
    obs = json.loads(Path(obs_file).read_text())
    verify_observation(obs)
    sid = hashlib.sha256(canonical_json(state).encode("ascii")).hexdigest()
    assert Path(state_file).name == sid + ".state.json"
    assert obs["state_id"] == sid and obs["state"] == state
    assert state["cors"]["allow_origin_wildcard"] is True and state["cors"]["allow_credentials"] is True
    assert state["tool_visibility"]["unauthenticated_tools"] == []
    assert obs["report_hash"] == report["report_hash"]
    assert "STATE ID: " + sid in proc.stderr
    assert not (tmp_path / "mcp-authscan-evidence").exists()


def test_cli_default_dir_is_next_to_output(tmp_path, zero_auth_cors):
    proc = _run([zero_auth_cors, "--json", "--output", str(tmp_path / "r.json"), *AUTH], cwd=ROOT)
    assert proc.returncode == 1, proc.stderr
    assert len(glob.glob(str(tmp_path / "*.state.json"))) == 1
    assert len(glob.glob(str(tmp_path / "observation-*.json"))) == 1


def test_cli_same_boundary_same_state_id(tmp_path, zero_auth_cors):
    ids = []
    for _ in range(2):
        proc = _run([zero_auth_cors, "--evidence-dir", str(tmp_path), *AUTH], cwd=tmp_path)
        ids.append([ln for ln in proc.stderr.splitlines() if "STATE ID" in ln])
    assert ids[0] == ids[1] and ids[0]
    assert len(glob.glob(str(tmp_path / "*.state.json"))) == 1


def test_cli_write_failure_exits_4(tmp_path, zero_auth_cors):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    proc = _run([zero_auth_cors, "--evidence-dir", str(blocker / "ev"), *AUTH], cwd=tmp_path)
    assert proc.returncode == 4
    assert "Evidence not written" in proc.stderr


def test_cli_halted_scan_emits_nothing(tmp_path):
    # Answers every POST with an initialize result and no OAuth metadata: discovery halts (exit 5).
    body = json.dumps({"result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                  "serverInfo": {"name": "h", "version": "0"}}}).encode()

    class Halt(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Halt)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}/mcp"
        proc = _run([url, "--evidence-dir", str(tmp_path / "ev"), *AUTH], cwd=tmp_path)
    finally:
        srv.shutdown()
        srv.server_close()
    assert proc.returncode == 5, proc.stderr
    assert "Discovery chain failed" in proc.stderr
    assert not (tmp_path / "ev").exists()


def test_cli_source_scan_emits_nothing(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text("print('hello')\n")
    proc = _run([str(src), "--evidence-dir", str(tmp_path / "ev"), *AUTH], cwd=tmp_path)
    assert proc.returncode in (0, 1, 5), proc.stderr
    assert not (tmp_path / "ev").exists()
