"""A target that is neither an existing path nor a URL with a scheme is refused (exit 3, stdout
empty) with one message that names both readings; the tool never guesses which one was meant.

Rule (monolith.missing_scheme), three branches and no heuristics:
  * the target contains "://"      -> URL handling, unchanged;
  * the target exists on disk      -> source mode, unchanged (an existing directory with no
                                      source files keeps its "no files examined" refusal);
  * anything else                  -> the refusal below.
There is deliberately no dot, port, leading-slash or host-vs-path test, so "localhost", bare
names, "./missing" and "/abs/missing" all get the same message as "example.com:443".
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUTH = ["--authorized-by", "Fixture runner", "--auth-basis", "Local test fixture",
        "--contact", "fixture@example.test"]
NEITHER = ("[!] Target validation failed: Target is neither an existing path nor a URL with a "
           "scheme. For a live endpoint use https://host/path. For source mode, pass a path that "
           "exists.")


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
    assert last == NEITHER, last
    assert "Scanning source code directory" not in proc.stderr
    assert proc.stdout == ""


@pytest.mark.parametrize("target", ["example.com:443", "127.0.0.1:9002", "[::1]:9002",
                                    "localhost:8080/mcp", "example.com/mcp", "example.com",
                                    "localhost/mcp", "localhost", "nosuchdir", "/abs/missing",
                                    "./missing"])
def test_neither_path_nor_url_gets_the_one_message(target, tmp_path):
    assert not os.path.exists(os.path.join(str(tmp_path), target))
    proc = _run(target, tmp_path)
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    assert proc.stdout == ""
    last = proc.stderr.strip().splitlines()[-1]
    assert last == NEITHER, last
    assert "Scanning source code directory" not in proc.stderr
    assert "no files examined" not in proc.stderr
    assert "did you mean" not in proc.stderr


def _srcdir(path):
    path.mkdir(parents=True)
    (path / "app.py").write_text("import os\nprint(os.getcwd())\n")
    return path


@pytest.mark.parametrize("form", ["absolute", "relative", "dot", "colon-named", "dotted",
                                  "localhost-named", "nested", "file"])
def test_existing_directory_still_runs_source_mode(form, tmp_path):
    name = {"colon-named": "h:80", "dotted": "example.com", "localhost-named": "localhost",
            "nested": "outer/inner"}.get(form, "srcdir")
    d = _srcdir(tmp_path / name)
    target = {"absolute": str(d), "relative": name, "dot": "./" + name, "colon-named": name,
              "dotted": name, "localhost-named": name, "nested": name,
              "file": name + "/app.py"}[form]
    proc = _run(target, tmp_path)
    assert proc.returncode == 0, (proc.returncode, proc.stderr)
    assert "Scanning source code directory" in proc.stderr
    assert "neither an existing path" not in proc.stderr


def test_missing_relative_directory_keeps_its_refusal(tmp_path):
    proc = _run("nosuchdir", tmp_path)
    assert proc.returncode == 3
    assert proc.stderr.strip().splitlines()[-1] == NEITHER


def test_existing_empty_directory_keeps_no_files_examined(tmp_path):
    (tmp_path / "emptydir").mkdir()
    proc = _run("emptydir", tmp_path)
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    assert proc.stdout == ""
    assert proc.stderr.strip().splitlines()[-1] == \
        "[!] Refused: no files examined in emptydir; no report produced"
    assert "neither an existing path" not in proc.stderr
