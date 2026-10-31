"""Coverage = (PASS + FAIL) / testable, testable = in_scope - EXCLUDED (owner decision, 2026-10-30).

Fixture 9002 (tests/test_fixture_with_findings.py, no client credentials): 9 declared, exactly
pkce-s256 and redirect-uri-exact EXCLUDED, 7 testable, 7 conclusive, so JSON coverage is 1.0 and
the printed Coverage line shows the same value over the same denominator.
"""
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_verdict_contract import AUTH, ROOT, start_fixture

PORT = 9002
FIXTURE = "test_fixture_with_findings.py"


def _run(extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    cmd = [sys.executable, "-m", "mcp_authscan", "http://127.0.0.1:%d/mcp" % PORT] + AUTH + extra
    return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, env=env,
                          stdin=subprocess.DEVNULL, timeout=120)


class CoverageOverTestable(unittest.TestCase):
    def test_9002_coverage_is_conclusive_over_testable_in_json_and_text(self):
        p = start_fixture(PORT, FIXTURE)
        try:
            j = _run(["--json"])
            t = _run([])
        finally:
            p.terminate()
            p.wait(timeout=5)
        report = json.loads(j.stdout[j.stdout.find("{"):])
        counts = report["counts"]
        excluded = sorted(x["name"] for x in report["probes"] if x["status"] == "EXCLUDED")
        self.assertEqual(9, counts["in_scope"])
        self.assertEqual(["pkce-s256", "redirect-uri-exact", "token-cors"], excluded)
        self.assertEqual(3, counts["EXCLUDED"])
        testable = counts["in_scope"] - counts["EXCLUDED"]
        self.assertEqual(6, testable)
        self.assertEqual(6, counts["PASS"] + counts["FAIL"])
        self.assertEqual(1.0, report["coverage"])
        lines = [l for l in t.stdout.splitlines() if l.startswith("Coverage:")]
        self.assertEqual(1, len(lines), "exactly one printed Coverage line: %r" % lines)
        m = re.match(r"Coverage: (\d+) of (\d+) testable probes reached a verdict \((\d+\.\d+)\)", lines[0])
        self.assertIsNotNone(m, "printed coverage line: %r" % lines[0])
        self.assertEqual((6, 6), (int(m.group(1)), int(m.group(2))))
        self.assertEqual(report["coverage"], float(m.group(3)))
        self.assertIn("3 excluded (token-cors, pkce-s256, redirect-uri-exact", lines[0])


if __name__ == "__main__":
    unittest.main()
