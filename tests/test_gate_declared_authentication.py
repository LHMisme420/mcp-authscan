"""Policy-only authentication declarations; real signed files and process exits."""
import json
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import report_signing, report_verify
from .test_gate_e2e import POLICY, bundle_v3


def _files(tmp_path, observation):
    key = Ed25519PrivateKey.generate()
    rp, pp, kp = bundle_v3(tmp_path, key, [('P1', 'PASS')], POLICY)
    report = json.loads(open(rp).read())
    if observation == 'zero-auth':
        report['findings'] = [{'rule': 'ZERO-AUTH', 'severity': 'MEDIUM',
                               'description': 'Synthetic unauthenticated initialize observation'}]
        report['findings_count'] = 1
        report['severity_counts'] = report_verify.severity_counts(report['findings'])
    elif observation == 'session':
        report['content_observed'] = {'version': 'test', 'session_established': True,
                                      'operations': ['initialize'], 'inspected': {}, 'reasons': []}
        report['sig_version'] = 4
        report['content_observed']['credential_context'] = 'anonymous'
    elif observation in ('discovery', 'other-endpoint', 'metadata', 'no-observation', 'resource-probe'):
        report['probes'].append({
            'name': 'resource-authservers' if observation == 'metadata' else
                    'anon-initialize' if observation == 'resource-probe' else 'unauthenticated-discovery',
            'status': 'EXCLUDED' if observation == 'no-observation' else
                      'FAIL' if observation == 'resource-probe' else 'PASS',
            'endpoint': 'https://other.invalid/mcp' if observation == 'other-endpoint' else report['target'],
            'http_status': 200,
        })
    elif observation == 'conditional':
        report['probes'][0]['status'] = 'NOT_OBSERVED'
    report['total_checks'] = len(report['probes'])
    report['report_hash'] = report_verify.compute(report, report['findings'])[0]
    report['signature'] = report_signing.sign_statement(
        key, report_verify.signed_content(report, report['findings']))
    with open(rp, 'w') as file:
        json.dump(report, file)
    return rp, pp, kp


def _run(paths, declared):
    rp, pp, kp = paths
    with open(pp) as file:
        policy = json.load(file)
    if declared is None:
        policy.pop('declared-authentication-required', None)
    else:
        policy['declared-authentication-required'] = declared
    with open(pp, 'w') as file:
        json.dump(policy, file)
    run = subprocess.run([sys.executable, '-m', 'mcp_authscan.policy_check', rp, pp, kp],
                         capture_output=True, text=True)
    assert run.stdout.strip(), (run.returncode, run.stderr)
    decision = json.loads(run.stdout)
    print(f'{declared=}: exit={run.returncode} {run.stdout.strip()}')
    return run, decision


@pytest.mark.parametrize('observation', ['discovery', 'zero-auth', 'session', 'resource-probe'])
def test_declared_authentication_contradicted_exits_nonzero(tmp_path, observation):
    paths = _files(tmp_path, observation)
    baseline, _ = _run(paths, None)
    disabled, _ = _run(paths, False)
    assert (disabled.returncode, disabled.stdout) == (baseline.returncode, baseline.stdout)
    contradicted, decision = _run(paths, True)
    assert contradicted.returncode == 1
    assert decision['verdict'] == 'CONTRADICTED', decision
    assert decision['check'] == 'AUTHENTICATION-REQUIRED'


@pytest.mark.parametrize('observation', ['clean', 'conditional', 'other-endpoint', 'metadata', 'no-observation'])
def test_declared_authentication_without_observation_preserves_exit(tmp_path, observation):
    paths = _files(tmp_path, observation)
    baseline, decision = _run(paths, None)
    assert baseline.returncode == 0
    assert decision['verdict'] == ('CONDITIONAL' if observation == 'conditional' else 'CLEAN')
    for enabled in (False, True):
        run, _ = _run(paths, enabled)
        assert (run.returncode, run.stdout) == (baseline.returncode, baseline.stdout)
