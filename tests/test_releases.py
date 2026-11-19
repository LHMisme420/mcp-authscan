"""mcp_authscan.releases: probe set -> release mapping, from the installed code alone."""
import json
import subprocess
import sys
from pathlib import Path

from mcp_authscan import __version__
from mcp_authscan.monolith import PROBE_SET_VERSION
from mcp_authscan.releases import PROBE_SET_RELEASES, describe, releases_for

ROOT = Path(__file__).resolve().parents[1]


def test_running_release_is_in_the_table():
    # A release that ships without its own entry fails here, before upload.
    assert __version__ in releases_for(PROBE_SET_VERSION)


def test_every_release_appears_once():
    seen = [v for vs in PROBE_SET_RELEASES.values() for v in vs]
    assert len(seen) == len(set(seen))


def test_published_history_as_read_from_pypi_wheels():
    # Spot checks against the wheels on PyPI (read 2026-11-19), including the non-monotonic step.
    assert releases_for("2026.11.11.1") == ["1.1.22"]
    assert releases_for("2026.11.10.1") == ["1.1.21", "1.1.23", "1.1.24"]
    assert releases_for("1.1.0") == ["1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6"]
    assert releases_for("never-shipped") == []


def test_describe_flags_a_report_from_another_release():
    info = describe("2026.11.10.1")
    assert info["releases"] == ["1.1.21", "1.1.23", "1.1.24"] and info["installed_matches"] is False


def test_cli_reads_a_report(tmp_path):
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"schema_version": 3, "probe_set_version": PROBE_SET_VERSION}))
    proc = subprocess.run([sys.executable, "-m", "mcp_authscan.releases", str(report)],
                          capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    assert out["releases"] == releases_for(PROBE_SET_VERSION) and out["installed_matches"] is True


def test_cli_unknown_stamp_exits_1():
    proc = subprocess.run([sys.executable, "-m", "mcp_authscan.releases", "--stamp", "1999.01.01.1"],
                          capture_output=True, text=True, timeout=30, cwd=ROOT)
    assert proc.returncode == 1 and json.loads(proc.stdout)["releases"] == []
