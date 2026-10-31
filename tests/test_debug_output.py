"""A default run prints no [DEBUG] lines on stderr; --verbose (-v) turns them on.

Before the fix two [DEBUG] lines (oauth_endpoints=..., token-cache-control: ...) went to
stderr on every live run.
"""
import subprocess
import sys
import unittest

from tests.test_verdict_contract import AUTH, ROOT, start_fixture

PORT, FIXTURE = 9002, "test_fixture_with_findings.py"


def run_scan(extra):
    cmd = [sys.executable, str(ROOT / "mcp_authscan.py"), "http://127.0.0.1:%d/mcp" % PORT,
           "--json"] + AUTH + extra
    return subprocess.run(cmd, cwd=str(ROOT), stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=180)


class DebugOutput(unittest.TestCase):

    def test_default_run_stderr_has_no_debug_and_verbose_restores_it(self):
        p = start_fixture(PORT, FIXTURE)
        try:
            default = run_scan([])
            verbose = run_scan(["--verbose"])
        finally:
            p.terminate()
            p.wait(timeout=5)
        self.assertIn(default.returncode, (0, 1), default.stderr[-1500:])
        self.assertNotIn("DEBUG", default.stderr)
        self.assertEqual(verbose.returncode, default.returncode, verbose.stderr[-1500:])
        self.assertIn("[DEBUG] oauth_endpoints=", verbose.stderr)
        self.assertIn("[DEBUG] token-cache-control:", verbose.stderr)
        self.assertEqual(default.stdout.count("report_hash"), 1)
