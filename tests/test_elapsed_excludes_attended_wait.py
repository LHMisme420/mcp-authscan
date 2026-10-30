"""Reported 'Elapsed Time' must not include the attended --acquire-token wait on stdin.

The test answers the consent prompt from a script after DELAY seconds. Before the fix the
reported elapsed time contained that delay (it measured the person, not the scan).
"""
import re
import subprocess
import sys
import threading
import time
import unittest

from tests.test_verdict_contract import AUTH, ROOT, scripted_consent, start_fixture

PORT, FIXTURE = 9004, "test_fixture_full_authserver.py"
DELAY = 4.0


class ElapsedExcludesAttendedWait(unittest.TestCase):

    def test_elapsed_time_excludes_scripted_consent_delay(self):
        p = start_fixture(PORT, FIXTURE)
        try:
            cmd = [sys.executable, str(ROOT / "mcp_authscan.py"), "http://127.0.0.1:%d/mcp" % PORT,
                   "--acquire-token"] + AUTH
            started = time.monotonic()
            scan = subprocess.Popen(cmd, cwd=str(ROOT), stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out = {}
            t = threading.Thread(target=lambda: out.update(stdout=scan.stdout.read()), daemon=True)
            t.start()
            prompt = re.compile(r"^\s+(http://127\.0\.0\.1:%d/authorize\?\S+)\s*$" % PORT)
            answered = False
            for line in scan.stderr:
                m = prompt.match(line)
                if m:
                    answer = scripted_consent(m.group(1))
                    time.sleep(DELAY)          # the attended wait
                    scan.stdin.write(answer + "\n")
                    scan.stdin.flush()
                    answered = True
                    break
            answer = None
            scan.stdin.close()
            scan.stderr.read()
            scan.wait(timeout=180)
            wall = time.monotonic() - started
            t.join(timeout=10)
        finally:
            p.terminate()
            p.wait(timeout=5)
        self.assertTrue(answered, "the consent prompt never appeared")
        self.assertGreaterEqual(wall, DELAY)
        m = re.search(r"^Elapsed Time: ([0-9.]+) seconds$", out.get("stdout", ""), re.M)
        self.assertIsNotNone(m, "no Elapsed Time line in the text report")
        elapsed = float(m.group(1))
        self.assertLess(elapsed, DELAY, "Elapsed Time %.2fs includes the %.1fs attended wait (wall %.2fs)"
                        % (elapsed, DELAY, wall))
        self.assertLess(elapsed, wall - DELAY + 0.5)
