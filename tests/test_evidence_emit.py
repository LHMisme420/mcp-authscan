"""Evidence emission: capture -> security-state-v1 + observation-v1 next to the report.

Restored from 90d3941 and rebased onto surface_capture.capture_surface().
Capture classification tests use real loopback HTTP; CLI tests run the real
scanner against tests/evidence_fixtures.py.
"""
import glob
import hashlib
import json
import os
import socket
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mcp_authscan import evidence_emit
from mcp_authscan.evidence.observation import verify_observation
from mcp_authscan.evidence.state import build_state, canonical_json
from mcp_authscan.surface_capture import capture_surface
from tests.evidence_fixtures import FixtureServer

ROOT = Path(__file__).resolve().parents[1]
EMPTY_ANON_ID = build_state({}, "anonymous")["state_id"]


def _capture(url, token=None):
    return capture_surface(url, token, True, ["127.0.0.1"])


def _closed_port_url():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}/mcp"


# ---- capture classification (real HTTP) -------------------------------------

def test_complete_anonymous_capture_gives_state():
    with FixtureServer(anonymous_tools=["list_docs"], prompts=["summarize"]) as (url, _):
        state, record = evidence_emit.classify_capture(_capture(url), "anonymous")
    assert state["tools"] == ["list_docs"] and state["prompts"] == ["summarize"]
    assert record == {"status": "complete", "reasons": []}


def test_refused_anonymous_capture_gives_empty_state_reason_in_record_only():
    with FixtureServer(gate_initialize=True, anonymous_tools=["list_docs"]) as (url, _):
        cap = _capture(url)
    state, record = evidence_emit.classify_capture(cap, "anonymous")
    assert cap["initialize_status"] == 401
    assert state["state_id"] == EMPTY_ANON_ID
    assert state["tools"] == state["prompts"] == state["resources"] == []
    assert record["status"] == "refused"
    assert "initialize returned status 401" in record["reasons"]
    assert "401" not in canonical_json(state)          # the reason never enters the state


def test_server_down_gives_no_state_not_an_empty_one():
    cap = _capture(_closed_port_url())
    assert cap["initialize_status"] is None
    state, reason = evidence_emit.classify_capture(cap, "anonymous")
    assert state is None
    assert "server not reached" in reason


def test_server_error_gives_no_state():
    cap = {"surface": {}, "captured": [], "reasons": ["initialize returned status 503"], "initialize_status": 503}
    state, reason = evidence_emit.classify_capture(cap, "anonymous")
    assert state is None and "HTTP 503" in reason


def test_partial_capture_gives_no_state():
    cap = {"surface": {"tools": []}, "captured": ["tools"], "reasons": ["prompts/list returned a JSON-RPC error"],
           "initialize_status": 200}
    assert evidence_emit.classify_capture(cap, "anonymous")[0] is None


def test_refused_credential_gives_no_authenticated_state():
    with FixtureServer(gate_initialize=True, token="right") as (url, _):
        state, reason = evidence_emit.classify_capture(_capture(url, token="wrong"), "authenticated")
    assert state is None and "credential refused (HTTP 401)" in reason


def test_capture_states_classes_follow_the_credential():
    with FixtureServer(token="t0k", anonymous_tools=["list_docs"], authenticated_tools=["list_docs", "write_doc"]) as (url, _):
        anon_only, _ = evidence_emit.capture_states(url, None, ["127.0.0.1"], capture=lambda *a: _capture(a[0], a[1]))
        both, skipped = evidence_emit.capture_states(url, "t0k", ["127.0.0.1"], capture=lambda *a: _capture(a[0], a[1]))
    assert [c for c, _, _ in anon_only] == ["anonymous"]
    assert [(c, s["tools"]) for c, s, _ in both] == [("anonymous", ["list_docs"]), ("authenticated", ["list_docs", "write_doc"])]
    assert skipped == []


# ---- observation --------------------------------------------------------------

def _payload(target):
    return {"target": target, "probes": [], "run_started_at": "2026-11-18T20:00:00+00:00",
            "probe_set_version": "2026.11.16.1", "report_hash": "ab" * 32,
            "counts": {"PASS": 0, "FAIL": 0, "NOT_OBSERVED": 0, "EXCLUDED": 0, "NOT_IMPLEMENTED": 0}}


def test_refused_observation_verifies_and_carries_reason():
    state = build_state({}, "anonymous")
    obs = evidence_emit.build_observation(state, {"status": "refused", "reasons": ["initialize returned status 401"]},
                                          _payload("HTTP://127.0.0.1:80/mcp"), scanner_version="x",
                                          ended_at=datetime(2026, 11, 18, 20, 0, 1, tzinfo=UTC))
    verify_observation(obs)
    assert obs["target"] == "http://127.0.0.1/mcp"
    assert obs["capture"]["reasons"] == ["initialize returned status 401"]


def test_refusal_on_a_non_empty_state_is_rejected():
    state = build_state({"tools": [{"name": "list_docs"}]}, "anonymous")
    obs = evidence_emit.build_observation(state, {"status": "refused", "reasons": ["initialize returned status 401"]},
                                          _payload("http://127.0.0.1/mcp"), scanner_version="x")
    with pytest.raises(ValueError, match="empty anonymous state"):
        verify_observation(obs)


def test_evidence_dir_precedence(tmp_path):
    assert evidence_emit.evidence_dir("/x/ev", str(tmp_path / "r.json")) == "/x/ev"
    assert evidence_emit.evidence_dir(None, str(tmp_path / "r.json")) == str(tmp_path)
    assert evidence_emit.evidence_dir(None, None) == os.path.join(os.getcwd(), "mcp-authscan-evidence")


# ---- end to end: the real CLI ---------------------------------------------------

AUTH = ["--allow-private", "--contact", "t@example.test", "--authorized-by", "T", "--auth-basis", "local fixture"]


def _run(args, cwd, token=None):
    env = dict(os.environ)
    env.pop("MCPAUTHSCAN_TOKEN", None)
    if token:
        env["MCPAUTHSCAN_TOKEN"] = token
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), *args], cwd=cwd,
                          capture_output=True, text=True, timeout=120, env=env)


def _observations(directory):
    return sorted((json.loads(Path(p).read_text()) for p in glob.glob(str(Path(directory) / "observation-*.json"))),
                  key=lambda o: o["state"]["access_class"])


def test_cli_emits_state_and_observation_next_to_report(tmp_path):
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = _run([url, "--json", "--output", str(tmp_path / "report.json"), *AUTH], cwd=tmp_path)
    assert proc.returncode == 1, proc.stderr                 # zero-auth finding
    report = json.loads((tmp_path / "report.json").read_text())
    assert json.loads(proc.stdout) == report                 # stdout is still exactly the report
    [obs] = _observations(tmp_path)
    verify_observation(obs)
    state_file = tmp_path / f"{obs['state_id']}.state.json"
    state = json.loads(state_file.read_text())
    assert state == obs["state"] and state["tools"] == ["list_docs"]
    assert hashlib.sha256(canonical_json({k: v for k, v in state.items() if k != "state_id"}).encode()).hexdigest() == obs["state_id"]
    assert report["evidence"] == {"scheme": "evidence-binding-v1",
                                  "states": [{"access_class": "anonymous", "state_id": obs["state_id"]}]}
    assert obs["report_hash"] == report["report_hash"]
    assert obs["capture"] == {"status": "complete", "reasons": []}
    assert not (tmp_path / "mcp-authscan-evidence").exists()


def test_cli_with_token_emits_both_classes(tmp_path):
    with FixtureServer(token="t0k", anonymous_tools=["list_docs"], authenticated_tools=["list_docs", "write_doc"]) as (url, _):
        proc = _run([url, "--json", "--evidence-dir", str(tmp_path), *AUTH], cwd=tmp_path, token="t0k")
    assert proc.returncode in (0, 1, 5), proc.stderr
    anon, auth = _observations(tmp_path)
    assert (anon["state"]["access_class"], anon["state"]["tools"]) == ("anonymous", ["list_docs"])
    assert (auth["state"]["access_class"], auth["state"]["tools"]) == ("authenticated", ["list_docs", "write_doc"])
    assert [s["access_class"] for s in json.loads(proc.stdout)["evidence"]["states"]] == ["anonymous", "authenticated"]


def test_cli_same_boundary_same_state_id(tmp_path):
    ids = []
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        for _ in range(2):
            proc = _run([url, "--json", "--evidence-dir", str(tmp_path), *AUTH], cwd=tmp_path)
            ids.append(json.loads(proc.stdout)["evidence"]["states"])
    assert ids[0] == ids[1]
    assert len(glob.glob(str(tmp_path / "*.state.json"))) == 1


def test_cli_evidence_write_failure_exits_4_and_writes_no_report(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = _run([url, "--json", "--output", str(tmp_path / "report.json"),
                     "--evidence-dir", str(blocker / "ev"), *AUTH], cwd=tmp_path)
    assert proc.returncode == 4
    assert "Evidence not written" in proc.stderr and "No report written" in proc.stderr
    assert proc.stdout == ""
    assert not (tmp_path / "report.json").exists()


def test_cli_halted_scan_emits_nothing(tmp_path):
    # Answers every POST with an initialize result and no OAuth metadata: discovery halts (exit 5).
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
        proc = _run([f"http://127.0.0.1:{srv.server_address[1]}/mcp", "--evidence-dir", str(tmp_path / "ev"), *AUTH],
                    cwd=tmp_path)
    finally:
        srv.shutdown()
        srv.server_close()
    assert proc.returncode == 5, proc.stderr
    assert not (tmp_path / "ev").exists()


def test_cli_source_scan_emits_nothing(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "server.py").write_text("print('hello')\n")
    proc = _run([str(src), "--json", "--evidence-dir", str(tmp_path / "ev"), *AUTH], cwd=tmp_path)
    assert proc.returncode in (0, 1, 5), proc.stderr
    assert "evidence" not in json.loads(proc.stdout)
    assert not (tmp_path / "ev").exists()


def test_gated_server_opening_up_is_a_regression_via_the_empty_state():
    """boundary-delta-v1 §5 gap 1, narrowed: a refused anonymous capture now leaves
    an empty anonymous state, so opening anonymous access later is BD-R2."""
    from mcp_authscan.evidence.delta import compute_delta
    with FixtureServer(gate_initialize=True, anonymous_tools=["delete_doc"]) as (url, config):
        closed, closed_rec = evidence_emit.classify_capture(_capture(url), "anonymous")
        config["gate_initialize"] = False
        opened, open_rec = evidence_emit.classify_capture(_capture(url), "anonymous")
    payload = _payload(url)
    before = evidence_emit.build_observation(closed, closed_rec, payload, scanner_version="x",
                                             ended_at=datetime(2026, 11, 18, 20, 0, 1, tzinfo=UTC))
    after = evidence_emit.build_observation(opened, open_rec, dict(payload, run_started_at="2026-11-18T21:00:00+00:00"),
                                            scanner_version="x", ended_at=datetime(2026, 11, 18, 21, 0, 1, tzinfo=UTC))
    d = compute_delta(before, after)
    assert (closed_rec["status"], open_rec["status"]) == ("refused", "complete")
    assert d["tools"]["added"] == ["delete_doc"]
    assert (d["classification"], d["rule"]) == ("AUTHORIZATION_REGRESSION", "BD-R2")
