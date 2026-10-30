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
        "token-cors": "EXCLUDED",
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
        "token-cors": "EXCLUDED",
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



# Acquired-token mode (--acquire-token), used only by the entries below. The consent step is
# scripted by the test: it reads the authorization URL the scanner prints to stderr, sends that
# GET to the fixture itself (the fixture approves at once with a 302), and writes the Location
# back to the scanner's stdin through a pipe. No TTY, no person. The callback address carries
# the authorization code, so neither it nor the scanner's raw output goes into any message.
ACQUIRED_FIXTURES = {
    9004: "test_fixture_full_authserver.py",
    9005: "test_fixture_basic_only_authserver.py",
}

ACQUIRED_EXPECTED = {
    9004: {
        "verdicts": {
            "issuer-identity": "PASS",
            "resource-binding": "PASS",
            "token-cache-control": "PASS",
            "token-cors": "PASS",
            "jwks-keys": "PASS",
            "password-grant": "PASS",
            "pkce-s256": "PASS",
            "redirect-uri-exact": "PASS",
            "client-auth": "PASS",
        },
        "coverage": 1.0,
        "excluded": 0,
        "exit_code": 0,
        "token_revocation_populated": True,
    },
    # 9005: the 9004 server accepting client_secret_basic only. A client registered with
    # token_endpoint_auth_method client_secret_basic must send HTTP Basic (RFC 6749 2.3.1) at the
    # token exchange and at revocation; a secret in the body is refused like no credentials.
    9005: {
        "verdicts": {
            "issuer-identity": "PASS",
            "resource-binding": "PASS",
            "token-cache-control": "PASS",
            "token-cors": "PASS",
            "jwks-keys": "PASS",
            "password-grant": "PASS",
            "pkce-s256": "PASS",
            "redirect-uri-exact": "PASS",
            "client-auth": "PASS",
        },
        "coverage": 1.0,
        "excluded": 0,
        "exit_code": 0,
        "token_revocation_populated": True,
    },
}


import re
import threading
import urllib.error
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def scripted_consent(authorize_url):
    """The fixture's answer to the authorization request: its Location header, or ""."""
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(authorize_url, timeout=10).close()
    except urllib.error.HTTPError as e:
        return e.headers.get("Location", "") if 300 <= e.code < 400 else ""
    return ""


def scan_acquired(port):
    """Run the scanner with --acquire-token and answer its one prompt from the test.

    Returns (returncode, report dict or None, consent_answered flag)."""
    url = "http://127.0.0.1:%d/mcp" % port
    cmd = [sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json",
           "--acquire-token"] + AUTH
    p = subprocess.Popen(cmd, cwd=str(ROOT), stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True)
    chunks = {"out": "", "err": ""}

    def drain(name, stream):
        chunks[name] = stream.read()

    t_out = threading.Thread(target=drain, args=("out", p.stdout), daemon=True)
    t_out.start()
    prompt = re.compile(r"^\s+(http://127\.0\.0\.1:%d/authorize\?\S+)\s*$" % port)
    answered = False
    for line in p.stderr:
        m = prompt.match(line)
        if m:
            p.stdin.write(scripted_consent(m.group(1)) + "\n")
            answered = True
            break
    try:
        p.stdin.close()
    except OSError:
        pass
    t_err = threading.Thread(target=drain, args=("err", p.stderr), daemon=True)
    t_err.start()
    try:
        p.wait(timeout=180)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait(timeout=5)
    t_out.join(timeout=5)
    t_err.join(timeout=5)
    out = chunks["out"]
    i = out.find("{")
    report = json.loads(out[i:]) if i >= 0 else None
    return p.returncode, report, answered


class AcquiredVerdictContract(unittest.TestCase):

    def test_acquired_mode_verdicts_coverage_and_revocation(self):
        for port, filename in ACQUIRED_FIXTURES.items():
            exp = ACQUIRED_EXPECTED[port]
            with self.subTest(port=port):
                p = start_fixture(port, filename)
                try:
                    rc, report, answered = scan_acquired(port)
                finally:
                    p.terminate()
                    p.wait(timeout=5)
                self.assertTrue(answered, "scanner never printed the authorization URL prompt")
                self.assertIsNotNone(report, "no JSON report on stdout")
                got = {}
                collect(report, got)
                diff = {}
                for k, want in exp["verdicts"].items():
                    if got.get(k) != want:
                        diff[k] = (want, got.get(k))
                self.assertEqual({}, diff, "expected vs got: %s" % diff)
                self.assertEqual(exp["coverage"], report.get("coverage"), "coverage")
                self.assertEqual(exp["excluded"], report["counts"]["EXCLUDED"], "excluded")
                self.assertEqual(exp["exit_code"], rc, "exit code")
                regs = report.get("client_registration") or []
                self.assertEqual(1, len(regs), "client_registration entries")
                self.assertEqual(exp["token_revocation_populated"],
                                 bool(regs[0].get("token_revocation")),
                                 "token_revocation populated")


# Plain mode (no --acquire-token) against the same 9004 server as the acquired entry above.
# Registration runs in plain mode too, so the token-cors probe does carry a client credential and
# a 2xx reaches a verdict: token-cors is judged on the token response and PASSES. Coverage 9 of 9.
# Both 9004 entries must hold.
PLAIN_FULL_FIXTURES = {
    9004: "test_fixture_full_authserver.py",
}

PLAIN_FULL_EXPECTED = {
    9004: {
        "verdicts": {
            "issuer-identity": "PASS",
            "resource-binding": "PASS",
            "token-cache-control": "PASS",
            "token-cors": "PASS",
            "jwks-keys": "PASS",
            "password-grant": "PASS",
            "pkce-s256": "PASS",
            "redirect-uri-exact": "PASS",
            "client-auth": "PASS",
        },
        "coverage": 1.0,
        "excluded": 0,
        "exit_code": 0,
    },
}


def scan_plain(port):
    """Run the scanner without --acquire-token, stdin closed. Returns (returncode, report or None)."""
    url = "http://127.0.0.1:%d/mcp" % port
    cmd = [sys.executable, str(ROOT / "mcp_authscan.py"), url, "--json"] + AUTH
    r = subprocess.run(cmd, cwd=str(ROOT), stdin=subprocess.DEVNULL, capture_output=True,
                       text=True, timeout=180)
    i = r.stdout.find("{")
    return r.returncode, (json.loads(r.stdout[i:]) if i >= 0 else None)


class PlainFullAuthServerContract(unittest.TestCase):

    def test_plain_mode_token_cors_not_observed_eight_of_nine(self):
        for port, filename in PLAIN_FULL_FIXTURES.items():
            exp = PLAIN_FULL_EXPECTED[port]
            with self.subTest(port=port):
                p = start_fixture(port, filename)
                try:
                    rc, report = scan_plain(port)
                finally:
                    p.terminate()
                    p.wait(timeout=5)
                self.assertIsNotNone(report, "no JSON report on stdout")
                got = {}
                collect(report, got)
                diff = {k: (want, got.get(k)) for k, want in exp["verdicts"].items() if got.get(k) != want}
                self.assertEqual({}, diff, "expected vs got: %s" % diff)
                self.assertEqual(exp["coverage"], report.get("coverage"), "coverage")
                self.assertEqual(exp["excluded"], report["counts"]["EXCLUDED"], "excluded")
                self.assertEqual(exp["exit_code"], rc, "exit code")
