import base64
import json
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from mcp_authscan import policy_check, report_signing, report_verify


def pub(k):
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def build(key, statuses):
    payload = {
        'schema_version': 3,
        'hash_scheme': 'verdict-v3',
        'tool_version': '1.1.34',
        'probe_set_version': '2026.11.19.3',
        'target': 'https://example.invalid/mcp',
        'scan_mode': 'anonymous',
        'counts': {},
        'coverage': {},
        'completed': True,
        'probes': [{'name': n, 'status': s} for n, s in statuses],
        'status': 'completed',
        'total_checks': 2,
        'findings_count': 0,
        'severity_counts': report_verify.severity_counts([]),
        'findings': [],
    }
    got, covered, content = report_verify.compute(payload, [], include_bytes=True)
    payload['report_hash'] = got
    payload['sig_version'] = 1
    payload['signature'] = report_signing.sign_statement(key, content)
    return payload


def bundle(tmp, key, statuses, policy):
    payload = build(key, statuses)
    kid = payload['signature']['key_id']
    rp = tmp / 'report.json'
    pp = tmp / 'policy.json'
    kp = tmp / 'keys.json'
    rp.write_text(json.dumps(payload))
    pol = dict(policy)
    pol['trusted-signers'] = [kid]
    pp.write_text(json.dumps(pol))
    kp.write_text(json.dumps([{'key_id': kid, 'alg': 'ed25519', 'public_key': pub(key)}]))
    return str(rp), str(pp), str(kp)


POLICY = {'required-probes': ['P1'], 'acceptable-verdicts': ['NOT_OBSERVED', 'EXCLUDED'], 'forbidden-findings': []}


def test_unresolved_probe_cannot_read_clean(tmp_path):
    key = Ed25519PrivateKey.generate()
    rp, pp, kp = bundle(tmp_path, key, [('P1', 'NOT_OBSERVED'), ('P2', 'PASS')], POLICY)
    out = policy_check.evaluate(rp, pp, kp)
    assert out['verdict'] == 'CONDITIONAL', out
    assert 'P1' in out['detail'], out


def test_resolved_probes_read_clean(tmp_path):
    key = Ed25519PrivateKey.generate()
    rp, pp, kp = bundle(tmp_path, key, [('P1', 'PASS'), ('P2', 'PASS')], POLICY)
    out = policy_check.evaluate(rp, pp, kp)
    assert out['verdict'] == 'CLEAN', out


def test_cli_prints_a_decision(tmp_path):
    key = Ed25519PrivateKey.generate()
    rp, pp, kp = bundle(tmp_path, key, [('P1', 'PASS')], POLICY)
    run = subprocess.run([sys.executable, '-m', 'mcp_authscan.policy_check', rp, pp, kp], capture_output=True, text=True)
    assert run.stdout.strip(), run.stderr
    assert json.loads(run.stdout.strip())['verdict'] == 'CLEAN', run.stdout