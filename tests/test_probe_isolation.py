"""Probe set 2026.11.19.2: one probe raising cannot end the scan.

From 367ea5f (2026-11-16) probe 15 built a PASS from a 401 with an empty body and no headers;
record() refused it, the ValueError reached the CLI, and the scan ended "Internal scan error",
exit 4, no report (tests/test_halted_scan_exit.py). Probe 15 now records the headers it saw, and
every probe runs through _common.isolated: a raising probe is NOT_OBSERVED for that probe alone.
"""
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from mcp_authscan import _common, target_probes
from mcp_authscan.errors import EgressRefusalError


def _boom(*a, **k):
    raise ValueError("synthetic probe failure")


def test_isolated_turns_a_raise_into_not_observed(capsys):
    r = _common.isolated(15, "alternate transport on the same host", _boom, endpoint="http://x/mcp")
    assert r.status == "NOT_OBSERVED"
    assert "ValueError: synthetic probe failure" in r.limitation
    assert "probe 15" in capsys.readouterr().err


def test_isolated_lets_scope_refusal_through():
    def refuse(*a, **k):
        raise EgressRefusalError("outside scope")
    with pytest.raises(EgressRefusalError):
        _common.isolated(4, "token-cors", refuse)


def test_isolated_redacts_a_token_in_the_exception():
    def leak(*a, **k):
        raise ValueError('{"access_token": "should-not-appear"}')
    r = _common.isolated(4, "token-cors", leak)
    assert "should-not-appear" not in r.limitation


def test_target_probes_survive_a_raising_probe(monkeypatch):
    monkeypatch.setattr(target_probes, "altprobe", _boom)
    records, _ = target_probes.run_target_probes("http://127.0.0.1:9/mcp", allowed_hosts={"127.0.0.1"},
                                                 allow_private=True)
    by_id = {str(r.probe_id): r for r in records}
    assert by_id["15"].status == "NOT_OBSERVED"
    assert len(records) == 3


def test_fingerprint_still_sees_every_isolated_probe():
    # Wrapping the calls in isolated() first made the probe order empty, which would let a
    # reordered or dropped probe pass the stamp test unnoticed.
    from tests.probe_set_fingerprint import _Module, _probe_order
    order = _probe_order(_Module("oauth_probes_v2"))
    assert order[0] == "probe_issuer_identity" and order[-1] == "probe_token_audience"
    assert len(order) == 12


class Halted(BaseHTTPRequestHandler):
    def do_POST(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Bearer realm=demo")
        self.end_headers()

    def do_GET(self):
        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_cli_writes_a_report_when_a_probe_raises(tmp_path):
    srv = HTTPServer(("127.0.0.1", 0), Halted)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    target = "http://127.0.0.1:%d/mcp" % srv.server_address[1]
    out = tmp_path / "report.txt"
    runner = ("import sys; import mcp_authscan.target_probes as t\n"
              "def boom(*a, **k): raise ValueError('synthetic probe failure')\n"
              "t.altprobe = boom\n"
              "from mcp_authscan.cli_wrapper import main; sys.exit(main())")
    try:
        p = subprocess.run([sys.executable, "-c", runner, target, "--allow-private", "--allow-host", "127.0.0.1",
                            "--authorized-by", "test", "--auth-basis", "loopback fixture",
                            "--contact", "scanner-test@example.invalid", "--output", str(out)],
                           capture_output=True, text=True, timeout=90, cwd=str(tmp_path))
    finally:
        srv.shutdown()
    assert "Internal scan error" not in p.stderr, p.stderr[-800:]
    assert p.returncode == 5, (p.returncode, p.stderr[-800:])
    assert out.exists() and "INCOMPLETE" in out.read_text().upper()
    assert "probe 15" in p.stderr
