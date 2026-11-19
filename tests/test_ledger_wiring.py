"""Scanner -> boundary-ledger-v1: where rows go, what they carry, and failure.

- default ledger is per user (~/.config/mcp-authscan/ledgers), keyed by
  target, so runs with different --output paths meet in one chain;
- the signed report names its chain (ledger key) and the head it extends;
- rows carry the report_hash and their own signature; signed runs only;
- any failure exits 4 with no report and no row (all-or-nothing).
"""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import evidence_emit
from mcp_authscan.evidence.delta import delta_from_ledger
from mcp_authscan.evidence.ledger import SIGNED, attestation_status, read_ledger
from mcp_authscan.report_signing import sign_statement
from tests.evidence_fixtures import FixtureServer

ROOT = Path(__file__).resolve().parents[1]
AUTH = ["--allow-private", "--contact", "t@example.test", "--authorized-by", "T", "--auth-basis", "local fixture"]


@pytest.fixture
def env(tmp_path):
    """Isolated HOME and an env-var signing key; returns (env, published keys)."""
    home = tmp_path / "home"
    home.mkdir()
    key = Ed25519PrivateKey.generate()
    key_file = tmp_path / "k.pem"
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    e = dict(os.environ, HOME=str(home), MCP_AUTHSCAN_SIGNING_KEY=str(key_file),
             PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    for var in ("MCPAUTHSCAN_TOKEN", "MCP_AUTHSCAN_LEDGER_DIR"):
        e.pop(var, None)
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = [{"key_id": sign_statement(key, b"x")["key_id"], "alg": "ed25519",
             "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")}]
    return e, keys


def _run(url, out, env, *extra, sign=True, token=None):
    e = dict(env)
    if token:
        e["MCPAUTHSCAN_TOKEN"] = token
    out.parent.mkdir(parents=True, exist_ok=True)
    args = [sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json", "--output", str(out),
            "--evidence-dir", str(out.parent / "ev"), *(["--sign"] if sign else []), *extra, *AUTH]
    return subprocess.run(args, capture_output=True, text=True, timeout=120, env=e, cwd=out.parent)


def _default_root(env):
    return Path(env["HOME"]) / ".config" / "mcp-authscan" / "ledgers"


def _ledger(root, url, klass):
    return Path(evidence_emit.ledger_path(str(root), url, klass))


def test_runs_with_different_outputs_meet_in_one_default_chain(tmp_path, env):
    e, keys = env
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, cfg):
        first = _run(url, tmp_path / "a" / "report.json", e)
        cfg["anonymous_tools"] = ["list_docs", "write_doc"]
        second = _run(url, tmp_path / "b" / "report.json", e)
    assert first.returncode == second.returncode == 1, second.stderr        # zero-auth finding, not 4
    r1 = json.loads((tmp_path / "a" / "report.json").read_text())
    r2 = json.loads((tmp_path / "b" / "report.json").read_text())
    path = _ledger(_default_root(e), url, "anonymous")
    lines = read_ledger(path, keys)
    assert [row["record"]["report_hash"] for row in lines[1:]] == [r1["report_hash"], r2["report_hash"]]
    assert [attestation_status(lines[0], row, keys) for row in lines[1:]] == [SIGNED, SIGNED]
    [b1], [b2] = r1["evidence"]["states"], r2["evidence"]["states"]
    key = evidence_emit.ledger_key(url, "anonymous")
    assert (b1["ledger"], b1["ledger_head"]) == (key, None)
    assert (b2["ledger"], b2["ledger_head"]) == (key, b1["state_id"])     # report B names the head it extends
    assert str(Path(e["HOME"])) not in json.dumps(r2)                     # no machine path in the report
    assert str(path) in second.stderr


def test_ledger_dir_precedence(tmp_path, env):
    e, keys = env
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        _run(url, tmp_path / "a" / "r.json", dict(e, MCP_AUTHSCAN_LEDGER_DIR=str(tmp_path / "from-env")))
        _run(url, tmp_path / "b" / "r.json", dict(e, MCP_AUTHSCAN_LEDGER_DIR=str(tmp_path / "from-env")),
             "--ledger-dir", str(tmp_path / "from-flag"))
    assert _ledger(tmp_path / "from-env", url, "anonymous").exists()
    assert _ledger(tmp_path / "from-flag", url, "anonymous").exists()
    assert not _default_root(e).exists()


def test_unsigned_run_records_nothing(tmp_path, env):
    e, _ = env
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = _run(url, tmp_path / "r.json", e, sign=False)
    assert proc.returncode == 1, proc.stderr
    assert not _default_root(e).exists()
    [entry] = json.loads((tmp_path / "r.json").read_text())["evidence"]["states"]
    assert (entry["ledger"], entry["ledger_head"]) == (None, None)


def test_ledger_unsigned_rows_cannot_satisfy_a_delta(tmp_path, env):
    e, keys = env
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, cfg):
        proc = _run(url, tmp_path / "a" / "r.json", e, "--ledger-unsigned", sign=False)
        cfg["anonymous_tools"] = ["list_docs", "write_doc"]
        _run(url, tmp_path / "b" / "r.json", e, "--ledger-unsigned", sign=False)
    assert proc.returncode == 1, proc.stderr
    lines = read_ledger(_ledger(_default_root(e), url, "anonymous"), keys)
    assert [row["record"]["attestation"] for row in lines[1:]] == [None, None]
    obs = json.loads(next((tmp_path / "b" / "ev").glob("observation-*.json")).read_text())
    with pytest.raises(ValueError, match="UNSIGNED"):
        delta_from_ledger(lines[:2], obs, keys)


def test_ledger_unsigned_requires_json():
    proc = subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), "unused", "--ledger-unsigned", *AUTH],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 2 and "--ledger-unsigned requires --json" in proc.stderr


def _assert_nothing_written(proc, out):
    assert proc.returncode == 4, proc.stderr
    assert proc.stdout == ""
    assert not out.exists()
    assert "No report written" in proc.stderr


def test_all_or_nothing_across_classes(tmp_path, env):
    e, _ = env
    root = _default_root(e)
    with FixtureServer(token="t0k", anonymous_tools=["list_docs"], authenticated_tools=["list_docs", "write_doc"]) as (url, _):
        _ledger(root, url, "authenticated").mkdir(parents=True)        # authenticated ledger path is a directory
        proc = _run(url, tmp_path / "r.json", e, token="t0k")
    _assert_nothing_written(proc, tmp_path / "r.json")
    assert not _ledger(root, url, "anonymous").exists()              # the other class did not land either


def test_tampered_ledger_refused_before_signing_and_left_untouched(tmp_path, env):
    e, _ = env
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, cfg):
        assert _run(url, tmp_path / "a" / "r.json", e).returncode == 1
        path = _ledger(_default_root(e), url, "anonymous")
        header, row = path.read_text().splitlines()
        tampered_row = json.loads(row)
        tampered_row["tools"] = ["delete_doc"]
        tampered = header + "\n" + json.dumps(tampered_row) + "\n"
        path.write_text(tampered)
        cfg["anonymous_tools"] = ["list_docs", "write_doc"]
        proc = _run(url, tmp_path / "b" / "r.json", e)
    _assert_nothing_written(proc, tmp_path / "b" / "r.json")
    assert "Ledger refused (anonymous)" in proc.stderr and "line 2: state_id: does not match content" in proc.stderr
    assert path.read_text() == tampered


def test_foreign_header_refused(tmp_path, env):
    e, _ = env
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        path = _ledger(_default_root(e), url, "anonymous")
        path.parent.mkdir(parents=True)
        foreign = json.dumps({"schema": "boundary-ledger-v1", "target": "https://other.example.com/mcp",
                              "access_class": "anonymous"}) + "\n"
        path.write_text(foreign)
        proc = _run(url, tmp_path / "r.json", e)
    _assert_nothing_written(proc, tmp_path / "r.json")
    assert "target: ledger is for 'https://other.example.com/mcp'" in proc.stderr
    assert path.read_text() == foreign


def test_unwritable_report_records_no_row(tmp_path, env):
    """The report is staged before the ledger commit: if it cannot be written, no row lands."""
    e, _ = env
    out = tmp_path / "missing-dir" / "r.json"           # parent does not exist: staging the report fails
    with FixtureServer(anonymous_tools=["list_docs"]) as (url, _):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json", "--sign", "--output", str(out),
             "--evidence-dir", str(tmp_path / "ev"), *AUTH], capture_output=True, text=True, timeout=120,
            env=e, cwd=tmp_path)
    _assert_nothing_written(proc, out)
    assert "no ledger row recorded" in proc.stderr
    assert not _ledger(_default_root(e), url, "anonymous").exists()
