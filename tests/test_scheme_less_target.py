"""A scheme-less host:port target is refused (exit 3) naming the missing scheme; it never
silently falls into source mode. Real source-mode paths keep their previous behaviour.

Rule (monolith.missing_scheme): the target has no "://", does not exist on disk, and is
HOST:PORT[/path] where HOST is a hostname, IPv4 address or [IPv6] literal and PORT is 1-5
digits. An existing path always wins, so a directory literally named "h:80" still scans.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUTH = ["--authorized-by", "Fixture runner", "--auth-basis", "Local test fixture",
        "--contact", "fixture@example.test"]


def _run(target, cwd):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    env["PYTHONPATH"] = str(ROOT)
    return subprocess.run([sys.executable, "-m", "mcp_authscan", target] + AUTH, cwd=str(cwd),
                          capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL,
                          timeout=60)


@pytest.mark.parametrize("target", ["127.0.0.1:9002", "example.com:443", "localhost:8080/mcp",
                                    "[::1]:9002"])
def test_bare_host_port_is_refused_naming_the_scheme(target, tmp_path):
    proc = _run(target, tmp_path)
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    last = proc.stderr.strip().splitlines()[-1]
    assert last == ("[!] Target validation failed: target %s has no scheme; did you mean https://%s ?"
                    % (target, target)), last
    assert "Scanning source code directory" not in proc.stderr
    assert proc.stdout == ""


def _srcdir(path):
    path.mkdir()
    (path / "app.py").write_text("import os\nprint(os.getcwd())\n")
    return path


@pytest.mark.parametrize("form", ["absolute", "relative", "dot", "colon-named"])
def test_existing_directory_still_runs_source_mode(form, tmp_path):
    name = "h:80" if form == "colon-named" else "srcdir"
    d = _srcdir(tmp_path / name)
    target = {"absolute": str(d), "relative": name, "dot": "./" + name, "colon-named": name}[form]
    proc = _run(target, tmp_path)
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    assert "Scanning source code directory" in proc.stderr
    assert "has no scheme" not in proc.stderr


def test_missing_relative_directory_keeps_its_refusal(tmp_path):
    proc = _run("nosuchdir", tmp_path)
    assert proc.returncode == 3
    assert proc.stderr.strip().splitlines()[-1] == "[!] Refused: no files examined in nosuchdir; no report produced"
