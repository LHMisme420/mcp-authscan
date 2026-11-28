"""Regression tests for three answer-key observations (2026-11-23):
1. a finding appended after decide_exit left the report's exit code below its own findings;
2. a halted scan with one concluded probe printed PASS;
3. the non-MCP early exit printed a text VERDICT line on stdout under --json."""
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "bench" / "answer-key" / "fixtures"
from tests._scanner import SCANNER
AUTH = ["--contact", "lhmisme2011@gmail.com", "--authorized-by", "Leroy H. Mason",
        "--auth-basis", "Own fixture, local loopback", "--allow-private"]

needs_scanner = pytest.mark.skipif(SCANNER is None, reason="mcp-authscan not on PATH")


def _port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _scan(fixture, *extra, tmp_path):
    port = _port()
    proc = subprocess.Popen([sys.executable, str(FIX / (fixture + ".py")), str(port)],
                            cwd=ROOT, start_new_session=True)
    try:
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
                break
            except OSError:
                time.sleep(0.1)
        else:
            pytest.fail("fixture %s did not start" % fixture)
        cmd = [SCANNER, *extra, *AUTH, "--evidence-dir", str(tmp_path / "ev"),
               "http://127.0.0.1:%d/mcp" % port]
        # Anonymous fixtures must not inherit operator credentials.
        env = os.environ.copy()
        env.pop("MCPAUTHSCAN_TOKEN", None)
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=180, cwd=ROOT, env=env
        )
    finally:
        os.killpg(proc.pid, 15)
        proc.wait(timeout=5)


def test_verdict_grade_halted_is_never_pass():
    from mcp_authscan.monolith import verdict_grade
    counts = {"PASS": 1, "FAIL": 0}
    assert verdict_grade([], counts) == "PASS"
    assert verdict_grade([], counts, halted=True) == "INCONCLUSIVE"
    # an observed finding still grades by severity on a halted scan
    assert verdict_grade([{"severity": "HIGH"}], counts, halted=True) == "HIGH"


@needs_scanner
def test_late_zero_auth_finding_sets_exit(tmp_path):
    r = _scan("open_with_discovery", "--json", tmp_path=tmp_path)
    d = json.loads(r.stdout)
    sev = {f.get("severity") for f in d["findings"]}
    assert "HIGH" in sev
    assert d["exit_code"] == r.returncode == 1, (d["exit_code"], d["exit_condition"], r.returncode)
    assert d["exit_condition"] == "finding_at_or_above_high"


@needs_scanner
@pytest.mark.parametrize("fixture", ["open_noauth", "open_with_discovery", "closed_oauth", "closed_401"])
def test_report_exit_matches_process_exit(fixture, tmp_path):
    r = _scan(fixture, "--json", tmp_path=tmp_path)
    d = json.loads(r.stdout)
    assert d["exit_code"] == r.returncode
    order = {"CRITICAL": 0, "HIGH": 1}
    if any(order.get(f.get("severity"), 99) <= 1 for f in d["findings"]):
        assert r.returncode == 1


@needs_scanner
def test_halted_scan_brief_is_inconclusive(tmp_path):
    r = _scan("closed_401", "--brief", tmp_path=tmp_path)
    line = [x for x in r.stdout.splitlines() if x.startswith("VERDICT ")]
    assert line and line[0].startswith("VERDICT INCONCLUSIVE"), r.stdout
    assert r.returncode == 5


@needs_scanner
@pytest.mark.parametrize("fixture", ["html_page", "plaintext_200", "challenge_basic"])
def test_not_mcp_json_stdout_has_no_text(fixture, tmp_path):
    r = _scan(fixture, "--json", tmp_path=tmp_path)
    assert r.returncode == 4
    assert r.stdout.strip() == "", r.stdout
    assert "VERDICT NOT_OBSERVED" in r.stderr


@needs_scanner
def test_not_mcp_brief_still_prints_verdict(tmp_path):
    r = _scan("html_page", "--brief", tmp_path=tmp_path)
    assert r.returncode == 4
    assert r.stdout.strip().startswith("VERDICT NOT_OBSERVED")
