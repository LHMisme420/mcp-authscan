"""--allow-private-host: one exact private host, default off, through the real CLI."""
import json
import subprocess
import sys

import pytest

from mcp_authscan import monolith, oauth_probes_v2
from mcp_authscan.monolith import EgressRefusalError
from tests.test_exit_code_fixtures import ROOT, fixture

PORT = 9002  # fixture metadata hardcodes 9002
AUTH = ['--authorized-by', 'Fixture runner', '--auth-basis', 'Local test fixture',
        '--contact', 'fixture@example.test']


def run(host, *extra):
    return subprocess.run(
        [sys.executable, str(ROOT / 'mcp_authscan.py'), 'http://%s:%d/mcp' % (host, PORT), *AUTH, *extra],
        cwd=ROOT, capture_output=True, text=True, timeout=45)


def test_private_host_refused_without_flag():
    with fixture('test_fixture_with_findings.py', PORT):
        r = run('127.0.0.1', '--json')
    assert r.returncode == 3, r.stderr
    assert 'DNS rebinding protection' in r.stderr


def test_private_host_allowed_with_flag_and_written_to_scope():
    with fixture('test_fixture_with_findings.py', PORT):
        r = run('127.0.0.1', '--allow-private-host', '127.0.0.1', '--json')
    assert r.returncode == 1, r.stderr  # findings fixture: scan ran to completion
    payload = json.loads(r.stdout[r.stdout.find('{'):])
    assert payload['scope_private_host'] == '127.0.0.1'


def test_second_private_host_still_refused(monkeypatch):
    with fixture('test_fixture_with_findings.py', PORT):
        r = run('127.0.0.2', '--allow-private-host', '127.0.0.1', '--json')
    assert r.returncode == 3, r.stderr
    assert 'DNS rebinding protection' in r.stderr
    # Guarded fetch: the permitted host passes, a second private host is refused.
    monkeypatch.setattr(monolith, 'PRIVATE_HOST_PERMITTED', '127.0.0.1')
    assert oauth_probes_v2._resolve_pinned('http://127.0.0.1:1/', allow_private=False) == '127.0.0.1'
    with pytest.raises(EgressRefusalError):
        oauth_probes_v2._resolve_pinned('http://127.0.0.2:1/', allow_private=False)
    with pytest.raises(EgressRefusalError):
        oauth_probes_v2._resolve_pinned('http://localhost:1/', allow_private=False)
