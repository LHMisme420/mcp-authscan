#!/usr/bin/env python3
"""Regression tests for the optional Semgrep taint engine.

Skipped entirely when Semgrep is not installed (it is an opt-in extra), so a
default CI run without `mcp-authscan[taint]` stays green. Where Semgrep is
present, these assert the two guarantees that make the engine trustworthy:
a vulnerable source->sink flow fires, and a sanitized flow does not.

Fixtures are copied to a throwaway non-git directory because Semgrep, run inside
a git repo, scans only tracked files -- the copy makes the test independent of
whether the fixtures happen to be staged.
"""
import shutil
import tempfile
import unittest
from pathlib import Path

from mcp_authscan.taint_scan import run_taint_scan, semgrep_available

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "taint"


@unittest.skipUnless(semgrep_available(), "Semgrep not installed (pip install 'mcp-authscan[taint]')")
class TaintEngineTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="authscan-taint-")
        for f in FIXTURES.glob("*"):
            shutil.copy(f, Path(cls._tmp) / f.name)
        cls.findings = run_taint_scan(cls._tmp, strict=True)
        cls.by_file = {}
        for fnd in cls.findings:
            cls.by_file.setdefault(Path(fnd["file"]).name, []).append(fnd)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _rules(self, filename):
        return {f["rule"] for f in self.by_file.get(filename, [])}

    def test_ssrf_vuln_ts_fires(self):
        self.assertIn("T1-SSRF", self._rules("ssrf_vuln.ts"))

    def test_ssrf_vuln_go_fires(self):
        self.assertIn("T1-SSRF", self._rules("ssrf_vuln.go"))

    def test_cmdi_vuln_py_fires(self):
        self.assertIn("T2-CMDI", self._rules("cmdi_vuln.py"))

    def test_sanitized_ssrf_is_silent(self):
        self.assertEqual(self._rules("ssrf_safe.ts"), set())

    def test_sanitized_cmdi_is_silent(self):
        self.assertEqual(self._rules("cmdi_safe.py"), set())

    def test_taint_findings_are_gating_detectors(self):
        # Every taint finding is a HIGH-confidence detector, not a review-list item.
        for f in self.findings:
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["confidence"], "HIGH")


if __name__ == "__main__":
    unittest.main()
