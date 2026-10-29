import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path.cwd()
UNDECIDED = "UNDECIDED"

AUTH = [
    "--authorized-by", "Fixture runner",
    "--auth-basis", "Local test fixture",
    "--contact", "fixture@example.test",
    "--allow-private",
]

FIXTURES = {
    9002: "test_fixture_with_findings.py",
}

EXPECTED = {
    9002: {
        "token-cache-control": "PASS",
        "token-cors": "FAIL",
        "password-grant": "FAIL",
        "pkce-s256": "EXCLUDED",
        "redirect-uri-exact": "EXCLUDED",
        "issuer-identity": "PASS",  # issuer matches hostUNDECIDED,
        "resource-binding": "PASS",  # resource matches endpointUNDECIDED,
        "client-auth": "FAIL",  # token without client creds
    },
}

import json
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path.cwd()
UNDECIDED = "UNDECIDED"

AUTH = [
    "--authorized-by", "Fixture runner",
    "--auth-basis", "Local test fixture",
    "--contact", "fixture@example.test",
    "--allow-private",
]

FIXTURES = {
    9002: "test_fixture_with_findings.py",
}

EXPECTED = {
    9002: {
        "token-cache-control": "PASS",
        "token-cors": "FAIL",
        "password-grant": "FAIL",
        "pkce-s256": "EXCLUDED",
        "redirect-uri-exact": "EXCLUDED",
        "issuer-identity": "PASS",  # issuer matches hostUNDECIDED,
        "resource-binding": "PASS",  # resource matches endpointUNDECIDED,
        "client-auth": "FAIL",  # token without client creds
    },
}

class VerdictContract(unittest.TestCase):

    def test_every_probe_has_a_decided_verdict(self):
        for port, filename in FIXTURES.items():
            exp = EXPECTED[port]
            with self.subTest(port=port):
                p = start_fixture(port, filename)
                try:
                    got = scan_verdicts(port)
                finally:
                    p.terminate()
                    p.wait(timeout=5)
                missing = [k for k in exp if k not in got]
                self.assertEqual([], missing,
                                 "probe never reported: %s" % missing)
                und = [k for k, v in exp.items() if v == UNDECIDED]
                self.assertEqual([], und,
                                 "decide and say why: %s" % und)
                diff = {}
                for k, want in exp.items():
                    if got.get(k) != want:
                        diff[k] = (want, got.get(k))
                self.assertEqual({}, diff,
                                 "expected vs got: %s" % diff)



class VerdictContract(unittest.TestCase):

    def test_every_probe_has_a_decided_verdict(self):
        for port, filename in FIXTURES.items():
            exp = EXPECTED[port]
            with self.subTest(port=port):
                p = start_fixture(port, filename)
                try:
                    got = scan_verdicts(port)
                finally:
                    p.terminate()
                    p.wait(timeout=5)
                missing = [k for k in exp if k not in got]
                self.assertEqual([], missing,
                                 "probe never reported: %s" % missing)
                und = [k for k, v in exp.items() if v == UNDECIDED]
                now = {k: got.get(k) for k in und}
                self.assertEqual([], und,
                                 "decide and say why: %s now: %s"
                                 % (und, now))
                diff = {}
                for k, want in exp.items():
                    if got.get(k) != want:
                        diff[k] = (want, got.get(k))
                self.assertEqual({}, diff,
                                 "expected vs got: %s" % diff)


def start_fixture(port, filename):
    cmd = [sys.executable, str(ROOT / "tests" / filename), str(port)]
    p = subprocess.Popen(cmd, cwd=str(ROOT),
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
    for _ in range(100):
        if p.poll() is not None:
            raise RuntimeError(p.stderr.read().decode())
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return p
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("fixture did not start on %d" % port)

def start_fixture(port, filename):
    cmd = [sys.executable, str(ROOT / "tests" / filename), str(port)]
    p = subprocess.Popen(cmd, cwd=str(ROOT),
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
    for _ in range(100):
        if p.poll() is not None:
            raise RuntimeError(p.stderr.read().decode())
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
            return p
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("fixture did not start on %d" % port)

def scan_verdicts(port):
    url = "http://127.0.0.1:%d/mcp" % port
    cmd = [sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json"] + AUTH
    r = subprocess.run(cmd, cwd=str(ROOT), capture_output=True,
                       text=True, timeout=180)
    i = r.stdout.find("{")
    if i < 0:
        raise AssertionError("no JSON on stdout\n%s\n%s"
                             % (r.stdout[-800:], r.stderr[-800:]))
    out = {}
    collect(json.loads(r.stdout[i:]), out)
    return out

def collect(n, out):
    if isinstance(n, dict):
        if "name" in n and "status" in n:
            out[n["name"]] = n["status"]
            return
        for v in n.values():
            collect(v, out)
    elif isinstance(n, list):
        for v in n:
            collect(v, out)


