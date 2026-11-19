"""Scanner -> boundary-ledger-v1 append, and what happens when the append fails.

Rule under test: a run whose ledger append fails exits 4 and writes no
report, so no run ever exits carrying a report that reads as recorded.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from mcp_authscan import evidence_emit
from mcp_authscan.evidence import ledger
from mcp_authscan.evidence.ledger import append_observation, read_ledger
from mcp_authscan.evidence.state import build_state, compute_state_id
from tests.evidence_fixtures import FixtureServer

ROOT = Path(__file__).resolve().parents[1]
AUTH = ["--allow-private", "--contact", "t@example.test", "--authorized-by", "T", "--auth-basis", "local fixture"]


def _run(url, tmp, *extra, token=None):
    env = dict(os.environ, PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    env.pop("MCPAUTHSCAN_TOKEN", None)
    if token:
        env["MCPAUTHSCAN_TOKEN"] = token
    return subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json",
                           "--output", str(tmp / "report.json"), "--evidence-dir", str(tmp / "ev"), *extra, *AUTH],
                          capture_output=True, text=True, timeout=120, env=env, cwd=tmp)


def _ledger(root, url, klass):
    return Path(evidence_emit.ledger_path(str(root), url, klass))


def test_two_runs_append_one_row_per_target_and_class(tmp_path):
    root = tmp_path / "ledgers"
    with FixtureServer(token="t0k", anonymous_tools=["list_docs"], authenticated_tools=["list_docs", "write_doc"]) as (url, cfg):
        first = _run(url, tmp_path, "--ledger-dir", str(root), token="t0k")
        (tmp_path / "report.json").unlink()
        cfg["authenticated_tools"] = ["export_docs", "list_docs", "write_doc"]
        second = _run(url, tmp_path, "--ledger-dir", str(root), token="t0k")
    assert first.returncode == second.returncode == 1, second.stderr      # zero-auth finding, not 4
    report = json.loads((tmp_path / "report.json").read_text())
    anon = read_ledger(_ledger(root, url, "anonymous"))
    auth = read_ledger(_ledger(root, url, "authenticated"))
    assert anon[0] == {"schema": "boundary-ledger-v1", "target": url, "access_class": "anonymous"}
    assert auth[0] == {"schema": "boundary-ledger-v1", "target": url, "access_class": "authenticated"}
    assert len(anon) == 2                               # unchanged anonymous boundary: second run was a no-op
    assert len(auth) == 3 and auth[2]["previous_state_id"] == auth[1]["state_id"]
    assert {s["access_class"]: s["state_id"] for s in report["evidence"]["states"]} == {
        "anonymous": anon[-1]["state_id"], "authenticated": auth[-1]["state_id"]}
    assert "unchanged (state equals head)" in second.stderr


def test_default_ledger_dir_is_under_evidence_dir(tmp_path):
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = _run(url, tmp_path)
    assert proc.returncode == 1, proc.stderr
    assert len(read_ledger(_ledger(tmp_path / "ev" / "ledger", url, "anonymous"))) == 2


def _assert_no_report(proc, tmp_path):
    assert proc.returncode == 4, proc.stderr
    assert proc.stdout == ""
    assert not (tmp_path / "report.json").exists()
    assert "No report written" in proc.stderr


def test_unwritable_ledger_exits_4_without_report(tmp_path):
    blocker = tmp_path / "ledgers"
    blocker.write_text("not a directory")
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = _run(url, tmp_path, "--ledger-dir", str(blocker))
    _assert_no_report(proc, tmp_path)
    assert "Ledger not updated (anonymous)" in proc.stderr


def test_tampered_ledger_exits_4_without_report_and_is_left_untouched(tmp_path):
    root = tmp_path / "ledgers"
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, cfg):
        assert _run(url, tmp_path, "--ledger-dir", str(root)).returncode == 1
        (tmp_path / "report.json").unlink()
        path = _ledger(root, url, "anonymous")
        lines = path.read_text().splitlines()
        row = json.loads(lines[1])
        row["tools"] = ["delete_doc"]                    # content no longer matches its state_id
        tampered = lines[0] + "\n" + json.dumps(row) + "\n"
        path.write_text(tampered)
        cfg["anonymous_tools"] = ["list_docs", "write_doc"]
        proc = _run(url, tmp_path, "--ledger-dir", str(root))
    _assert_no_report(proc, tmp_path)
    assert "line 2: state_id: does not match content" in proc.stderr
    assert path.read_text() == tampered


def test_foreign_header_is_refused(tmp_path):
    root = tmp_path / "ledgers"
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        path = _ledger(root, url, "anonymous")
        path.parent.mkdir(parents=True)
        foreign = json.dumps({"schema": "boundary-ledger-v1", "target": "https://other.example.com/mcp",
                              "access_class": "anonymous"}) + "\n"
        path.write_text(foreign)
        proc = _run(url, tmp_path, "--ledger-dir", str(root))
    _assert_no_report(proc, tmp_path)
    assert "target: ledger is for 'https://other.example.com/mcp'" in proc.stderr
    assert path.read_text() == foreign


def test_partial_failure_names_rows_already_appended(tmp_path):
    root = tmp_path / "ledgers"
    with FixtureServer(token="t0k", anonymous_tools=["list_docs"], authenticated_tools=["list_docs", "write_doc"]) as (url, _):
        _ledger(root, url, "authenticated").mkdir(parents=True)    # authenticated ledger path is a directory
        proc = _run(url, tmp_path, "--ledger-dir", str(root), token="t0k")
    _assert_no_report(proc, tmp_path)
    assert "Ledger not updated (authenticated)" in proc.stderr
    assert "Ledger already updated by this run: anonymous" in proc.stderr
    assert len(read_ledger(_ledger(root, url, "anonymous"))) == 2


# ---- append is atomic -------------------------------------------------------------

def _obs(tools):
    state = build_state({"tools": [{"name": t} for t in tools]}, "anonymous")
    return {"schema": "observation-v1", "target": "https://mcp.example.com/mcp", "state_id": compute_state_id(state),
            "state": state, "observed_at": {"start": "2026-11-18T20:00:00Z", "end": "2026-11-18T20:00:01Z"},
            "scanner": {"name": "mcp-authscan", "version": "t", "probe_set_version": "t"},
            "coverage": {"in_scope": 0, "pass": 0, "fail": 0, "not_observed": 0, "excluded": 0},
            "not_observed": [], "excluded": []}


def test_failed_write_leaves_previous_ledger_intact(tmp_path, monkeypatch):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(["list_docs"]))
    before = path.read_bytes()

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(ledger.os, "replace", boom)
    with pytest.raises(OSError):
        append_observation(path, _obs(["list_docs", "write_doc"]))
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if ".tmp." in p.name] == []
    monkeypatch.undo()
    assert len(read_ledger(path)) == 2
