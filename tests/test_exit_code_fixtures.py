"""Exercise the actual root CLI against all seven documented exit-code cases.

Only loopback fixture processes started by this test are terminated. Never use
proof_all_exit_codes.sh here: it has a foreign cwd and globally kills Python.
"""
from contextlib import contextmanager
from pathlib import Path
import json
import socket
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUTH = [
    '--authorized-by', 'Fixture runner', '--auth-basis', 'Local test fixture',
    '--contact', 'fixture@example.test', '--allow-private',
]


@contextmanager
def fixture(filename, port):
    # Refuse to target an unrelated service already using the fixture port.
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', port))
    process = subprocess.Popen(
        [sys.executable, str(ROOT / 'tests' / filename), str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError(process.stderr.read().decode())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                time.sleep(.05)
        else:
            raise RuntimeError('Loopback fixture did not start')
        yield
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stderr.close()


class ExitCodeFixtureTests(unittest.TestCase):
    def check_exit(self, expected, port, args=AUTH):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'mcp_authscan.py'),
             f'http://127.0.0.1:{port}/mcp', *args],
            cwd=ROOT, capture_output=True, text=True, timeout=45,
        )
        self.assertEqual(result.returncode, expected,
                         f'Expected {expected}, got {result.returncode}\n'
                         f'{result.stdout}\n{result.stderr}')
        if expected == 1:
            self.assertRegex(result.stderr, r'password-grant\s+FAIL')
            self.assertRegex(result.stderr, r'client-auth\s+FAIL')
        if expected == 4:
            self.assertNotIn('preflight detected OAuth (401)', result.stderr)

    def test_exit_0_complete_clean_fixture(self):
        with fixture('test_fixture_coverage_100.py', 9000):
            self.check_exit(0, 9000)

    def test_exit_1_findings_fixture(self):
        with fixture('test_fixture_with_findings.py', 9002):
            self.check_exit(1, 9002, AUTH + ['--fail-on', 'high'])

    def test_exit_2_missing_authorization_basis(self):
        self.check_exit(2, 9000, [
            '--authorized-by', 'Fixture runner',
            '--contact', 'fixture@example.test', '--allow-private',
        ])

    def test_exit_3_unreachable_fixture(self):
        with socket.socket() as reserved:
            # A bound, non-listening port cannot belong to another target.
            reserved.bind(('127.0.0.1', 0))
            self.check_exit(3, reserved.getsockname()[1])

    def test_exit_4_not_mcp_fixture(self):
        with fixture('test_fixture_not_mcp.py', 9003):
            self.check_exit(4, 9003)

    def test_exit_5_incomplete_fixture(self):
        with fixture('test_fixture_coverage_incomplete.py', 9001):
            self.check_exit(5, 9001)

    def test_exit_6_invalid_usage(self):
        self.check_exit(6, 9000, AUTH + ['--fail-on', 'invalid'])


class ScopePayloadTests(unittest.TestCase):
    def payload(self, port, extra):
        result = subprocess.run(
            [sys.executable, str(ROOT / 'mcp_authscan.py'),
             'http://127.0.0.1:%d/mcp' % port, *AUTH, '--json', *extra],
            cwd=ROOT, capture_output=True, text=True, timeout=45,
        )
        self.assertEqual(result.returncode, 0,
                         'Expected 0, got %d\n%s' % (result.returncode, result.stderr))
        text = result.stdout
        start = text.find('{')
        self.assertGreaterEqual(start, 0, 'No JSON payload in stdout:\n' + text)
        return json.loads(text[start:])

    def test_supplied_scope_reaches_payload(self):
        with fixture('test_fixture_coverage_100.py', 9000):
            payload = self.payload(9000, ['--scope', 'Authorized MCP audit, fixtures only'])
            self.assertEqual(payload['scope'], 'Authorized MCP audit, fixtures only')

    def test_scope_falls_back_when_not_supplied(self):
        with fixture('test_fixture_coverage_100.py', 9000):
            payload = self.payload(9000, [])
            expected = 'OAuth authorization server configuration for http://127.0.0.1:9000/mcp'
            self.assertEqual(payload['scope'], expected)


class HtmlReportGuardTests(unittest.TestCase):
    def test_refuses_page_without_payload(self):
        from mcp_authscan import monolith
        out = ROOT / 'tests' / 'should-not-exist.html'
        if out.exists():
            out.unlink()
        with self.assertRaises(ValueError):
            monolith.generate_html_report([], 'http://127.0.0.1:9000/mcp', str(out))
        self.assertFalse(out.exists(), 'Refused call still wrote a page')
