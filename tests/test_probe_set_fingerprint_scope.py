"""The probe set fingerprint covers the probe set, not report accounting.

f707170 changed only how monolith.main counts and computes coverage, yet the fingerprint hashed
those assignments (a report_accounting component), so the stamp test demanded 2026.10.30.5 for an
unchanged probe set. Here a scratch copy of the package is mutated one way at a time and
re-fingerprinted: report-accounting edits must not move the fingerprint; probe logic and severity
edits must.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _fingerprint(tmp_path, path=None, old=None, new=None):
    work = tmp_path / "copy"
    shutil.copytree(ROOT / "mcp_authscan", work / "mcp_authscan",
                    ignore=shutil.ignore_patterns("__pycache__"))
    (work / "tests").mkdir()
    (work / "tests" / "__init__.py").write_text("")
    shutil.copy(ROOT / "tests" / "probe_set_fingerprint.py", work / "tests")
    if path:
        target = work / path
        src = target.read_text(encoding="utf-8")
        assert src.count(old) == 1, "anchor %r found %d times in %s" % (old, src.count(old), path)
        target.write_text(src.replace(old, new), encoding="utf-8")
    out = subprocess.run([sys.executable, "-c",
                          "from tests.probe_set_fingerprint import fingerprint; print(fingerprint()[0])"],
                         cwd=str(work), capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


ACCOUNTING = {
    "monolith.main counts assignment": (
        "mcp_authscan/monolith.py",
        '    canonical_payload["counts"] = counts\n',
        '    counts = dict(counts, PASS=counts["PASS"])\n    canonical_payload["counts"] = counts\n'),
    "monolith.main coverage assignment": (
        "mcp_authscan/monolith.py",
        'canonical_payload["coverage"] = round(coverage(counts), 4)',
        'canonical_payload["coverage"] = round(coverage(counts), 3)'),
    "counts.coverage()": (
        "mcp_authscan/counts.py",
        'return (counts["PASS"] + counts["FAIL"]) / float(testable(counts))',
        'return float(counts["PASS"] + counts["FAIL"]) / testable(counts)'),
}

PROBE_SET = {
    "probe logic (issuer-identity comparison)": (
        "mcp_authscan/oauth_probes_v2.py",
        "    if issuer_norm == base_url_norm:\n",
        "    if issuer_norm != base_url_norm:\n"),
    "probe severity (issuer missing HIGH -> MEDIUM)": (
        "mcp_authscan/oauth_probes_v2.py",
        'detail="issuer field is missing from OAuth metadata (required)",\n            severity="HIGH",',
        'detail="issuer field is missing from OAuth metadata (required)",\n            severity="MEDIUM",'),
}


@pytest.mark.parametrize("case", sorted(ACCOUNTING))
def test_report_accounting_change_does_not_move_fingerprint(tmp_path, case):
    base = _fingerprint(tmp_path / "base")
    assert _fingerprint(tmp_path / "mut", *ACCOUNTING[case]) == base


@pytest.mark.parametrize("case", sorted(PROBE_SET))
def test_probe_set_change_moves_fingerprint(tmp_path, case):
    base = _fingerprint(tmp_path / "base")
    assert _fingerprint(tmp_path / "mut", *PROBE_SET[case]) != base
