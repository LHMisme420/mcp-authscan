"""JSON "counts" comes from count_probes(), the same function the printed summary counts with.

On fixture 9002 the JSON counts must equal the counts the text report prints (PASSED, EXCLUDED,
NOT IMPLEMENTED, NOT OBSERVED, FINDINGS and the Coverage line) and count_probes() over the
records the JSON reports, with exactly count_probes()'s keys.
"""
import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_verdict_contract import AUTH, ROOT, start_fixture
from mcp_authscan._common import VALID_STATUSES
from mcp_authscan.counts import count_probes

PORT = 9002
FIXTURE = "test_fixture_with_findings.py"
PRINTED = {"PASS": "PASSED", "EXCLUDED": "EXCLUDED", "NOT_IMPLEMENTED": "NOT IMPLEMENTED",
           "NOT_OBSERVED": "NOT OBSERVED", "FAIL": "FINDINGS"}


def _run(extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPAUTHSCAN_")}
    cmd = [sys.executable, "-m", "mcp_authscan", "http://127.0.0.1:%d/mcp" % PORT] + AUTH + extra
    return subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, env=env,
                          stdin=subprocess.DEVNULL, timeout=120)


class JsonCountsSingleSource(unittest.TestCase):
    def test_9002_json_counts_equal_printed_counts_and_count_probes(self):
        p = start_fixture(PORT, FIXTURE)
        try:
            j = _run(["--json"])
            t = _run([])
        finally:
            p.terminate()
            p.wait(timeout=5)
        report = json.loads(j.stdout[j.stdout.find("{"):])
        counts = report["counts"]

        records = [SimpleNamespace(probe_id=x["probe_id"], status=x["status"]) for x in report["probes"]]
        self.assertEqual(count_probes(records), counts)
        self.assertEqual(set(VALID_STATUSES) | {"in_scope", "attempted"}, set(counts))

        printed = {}
        for status, label in PRINTED.items():
            m = [re.match(r"%s \((\d+)[,)]" % label, l) for l in t.stdout.splitlines()]
            m = [x for x in m if x]
            self.assertLessEqual(len(m), 1, label)
            printed[status] = int(m[0].group(1)) if m else 0
        self.assertEqual(printed, {s: counts[s] for s in PRINTED})
        cov = [l for l in t.stdout.splitlines() if l.startswith("Coverage:")]
        self.assertEqual(1, len(cov), cov)
        m = re.match(r"Coverage: (\d+) of (\d+) testable", cov[0])
        self.assertIsNotNone(m, cov[0])
        self.assertEqual((counts["PASS"] + counts["FAIL"], counts["in_scope"] - counts["EXCLUDED"]),
                         (int(m.group(1)), int(m.group(2))))


if __name__ == "__main__":
    unittest.main()
