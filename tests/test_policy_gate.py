import mcp_authscan.policy_check as pc
import json


def build(tmp, probes, required):
    report = {'probes': probes, 'findings': [], 'signature': 'x'}
    rp = tmp / 'report.json'
    rp.write_text(json.dumps(report))
    policy = {'trusted-signers': ['k'], 'required-probes': required, 'acceptable-verdicts': ['PASS'], 'forbidden-findings': []}
    pp = tmp / 'policy.json'
    pp.write_text(json.dumps(policy))
    return str(rp), str(pp)


def stub(monkeypatch):
    monkeypatch.setattr(pc, 'authenticity', lambda report, keys: 'SIGNED BY k')
    monkeypatch.setattr(pc, 'verify', lambda path: ('MATCH', 'deadbeefcafe'))


def test_required_miss_with_extra_passes_is_conditional(tmp_path, monkeypatch):
    stub(monkeypatch)
    probes = [{'name': 'A', 'status': 'NOT_OBSERVED'}, {'name': 'X1', 'status': 'PASS'}, {'name': 'X2', 'status': 'PASS'}, {'name': 'X3', 'status': 'PASS'}]
    rp, pp = build(tmp_path, probes, ['A'])
    e = pc.evaluate(rp, pp, {'k': 'pk'})
    assert e['verdict'] == 'CONDITIONAL', e
    assert 'A' in e['detail'], e


def test_all_required_pass_is_clean(tmp_path, monkeypatch):
    stub(monkeypatch)
    probes = [{'name': 'A', 'status': 'PASS'}, {'name': 'B', 'status': 'PASS'}]
    rp, pp = build(tmp_path, probes, ['A', 'B'])
    e = pc.evaluate(rp, pp, {'k': 'pk'})
    assert e['verdict'] == 'CLEAN', e
