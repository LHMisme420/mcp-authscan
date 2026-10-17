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

    def test_path_traversal_fires(self):
        self.assertIn("T3-PATH", self._rules("path_vuln.py"))
        self.assertIn("T3-PATH", self._rules("path_vuln.ts"))

    def test_sanitized_path_is_silent(self):
        self.assertEqual(self._rules("path_safe.py"), set())

    def test_sqli_fires(self):
        self.assertIn("T4-SQLI", self._rules("sqli_vuln.py"))
        self.assertIn("T4-SQLI", self._rules("sqli_vuln.ts"))

    def test_parameterized_sql_is_silent(self):
        # The value is bound as a parameter (separate arg), not built into the SQL
        # string -- the focus-metavariable must leave this untouched.
        self.assertEqual(self._rules("sqli_safe.py"), set())

    def test_ssti_fires(self):
        self.assertIn("T5-SSTI", self._rules("ssti_vuln.py"))
        self.assertIn("T5-SSTI", self._rules("ssti_vuln.ts"))

    def test_template_as_data_is_silent(self):
        # render_template("page.html", name=user): template fixed, user is data.
        self.assertEqual(self._rules("ssti_safe.py"), set())

    def test_eval_fires(self):
        self.assertIn("T6-EVAL", self._rules("eval_vuln.py"))
        self.assertIn("T6-EVAL", self._rules("eval_vuln.ts"))

    def test_eval_of_literal_is_silent(self):
        self.assertEqual(self._rules("eval_safe.py"), set())

    def test_deserialization_fires(self):
        self.assertIn("T7-DESER", self._rules("deser_vuln.py"))

    def test_safe_loader_is_silent(self):
        # yaml.safe_load is a distinct call from yaml.load -- must not be flagged.
        self.assertEqual(self._rules("deser_safe.py"), set())

    def test_taint_findings_are_gating_detectors(self):
        # Every taint finding is a HIGH-confidence detector, not a review-list item.
        for f in self.findings:
            self.assertEqual(f["severity"], "HIGH")
            self.assertEqual(f["confidence"], "HIGH")


@unittest.skipUnless(semgrep_available(), "Semgrep not installed (pip install 'mcp-authscan[taint]')")
class TaintEngineRealCodeTest(unittest.TestCase):
    """The taint engine against the research RCE routers: real (mock) MCP code where
    the vulnerable and hardened versions differ only by an allowlist validator. Taint
    must fire on one and stay silent on the other -- the distinction regex cannot make."""

    RESEARCH = Path(__file__).resolve().parent.parent / "research" / "mcp_stdio_rce"

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="authscan-rce-")
        for name in ("vulnerable_router.py", "hardened_router.py", "detector.py"):
            src = cls.RESEARCH / name
            if src.is_file():
                shutil.copy(src, Path(cls._tmp) / name)
        cls.by_file = {}
        for f in run_taint_scan(cls._tmp, strict=True):
            cls.by_file.setdefault(Path(f["file"]).name, []).append(f["rule"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def test_vulnerable_router_fires_cmdi(self):
        self.assertIn("T2-CMDI", self.by_file.get("vulnerable_router.py", []))

    def test_hardened_router_is_silent(self):
        self.assertEqual(self.by_file.get("hardened_router.py", []), [])


if __name__ == "__main__":
    unittest.main()
