"""Commands shown in the docs must be ones the CLI accepts.

Every `mcp-authscan ...` line in a fenced block of the docs below is checked against
`python3 -m mcp_authscan --help`: no `scan` verb, only options the parser lists, --fail-on
values from its choices, and the three authorization options a scan needs (the CLI exits 2
without them). Every `pip install -e PATH` / `python -m build PATH` must point at a
pyproject.toml whose version is mcp_authscan.__version__.
"""
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import mcp_authscan

ROOT = Path(__file__).resolve().parent.parent
DOCS = ["README.md", "mcp_authscan/README.md", "CONTRIBUTING.md",
        "docs/ci-quickstart.md", "docs/RELEASING.md"]
AUTH_OPTIONS = ("--authorized-by", "--auth-basis", "--contact")


def _fenced_commands(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    out, inside, buf = [], False, ""
    for raw in text.splitlines():
        if raw.strip().startswith("```"):
            inside, buf = not inside, ""
            continue
        if not inside:
            continue
        line = raw.split(" #", 1)[0].strip() if not raw.strip().startswith("#") else ""
        line = re.sub(r"^(?:-\s+)?(?:run:\s*)?", "", line)
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        line, buf = (buf + line).strip(), ""
        if line:
            out.append(line)
    return out


def _cli_help():
    env = dict(os.environ, COLUMNS="200")
    r = subprocess.run([sys.executable, "-m", "mcp_authscan", "--help"], capture_output=True,
                       text=True, env=env, stdin=subprocess.DEVNULL, timeout=60, cwd=str(ROOT))
    assert r.returncode == 0, r.stderr
    return r.stdout


def _commands(prefix_re):
    found = []
    for doc in DOCS:
        for line in _fenced_commands(doc):
            if re.match(prefix_re, line):
                found.append((doc, line))
    return found


def test_doc_scan_commands_are_accepted_by_the_cli():
    help_text = _cli_help()
    options = set(re.findall(r"(?<![\w-])(--?[A-Za-z][\w-]*)", help_text))
    fail_on = re.search(r"--fail-on \{([^}]*)\}", help_text).group(1).split(",")
    problems = []
    cmds = _commands(r"mcp-authscan(\s|$)")
    assert cmds, "no mcp-authscan commands found in %s" % DOCS
    for doc, line in cmds:
        argv = shlex.split(line)[1:]
        if argv and argv[0] == "scan":
            problems.append("%s: 'scan' verb the CLI rejects: %s" % (doc, line))
        for i, a in enumerate(argv):
            if a.startswith("-"):
                name = a.split("=", 1)[0]
                if name not in options:
                    problems.append("%s: unknown option %s: %s" % (doc, name, line))
                if name == "--fail-on" and i + 1 < len(argv) and argv[i + 1] not in fail_on:
                    problems.append("%s: --fail-on %s not in %s: %s" % (doc, argv[i + 1], fail_on, line))
        if not {"--help", "-h", "--version"} & set(argv):
            missing = [o for o in AUTH_OPTIONS if o not in argv]
            if missing:
                problems.append("%s: scan without %s (CLI exits 2): %s" % (doc, missing, line))
    assert not problems, "\n".join(problems)


def test_doc_install_and_build_paths_build_this_version():
    problems = []
    cmds = _commands(r"(pip install -e|python3? -m build)\b")
    assert cmds, "no install/build commands found in %s" % DOCS
    for doc, line in cmds:
        argv = shlex.split(line)
        rest = argv[3:]
        paths = [a for a in rest if not a.startswith("-")]
        if "--outdir" in rest:
            paths.remove(rest[rest.index("--outdir") + 1])
        target = ROOT / (paths[0] if paths else ".")
        pyproject = (target / "pyproject.toml").read_text(encoding="utf-8")
        version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)
        if version != mcp_authscan.__version__:
            problems.append("%s: %r builds version %s, package is %s"
                            % (doc, line, version, mcp_authscan.__version__))
    assert not problems, "\n".join(problems)
