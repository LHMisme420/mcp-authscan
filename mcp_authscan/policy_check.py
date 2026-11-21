import json
import sys

from mcp_authscan.report_verify import verify, authenticity


def evaluate(report_path, policy_path, keys_path):
    policy = json.load(open(policy_path))
    report = json.load(open(report_path))
    keys = json.load(open(keys_path)) if isinstance(keys_path, str) else keys_path
    trusted = {k if isinstance(k, str) else k.get('key-id') for k in policy.get('trusted-signers', [])}
    a = authenticity(report, keys)
    if not a.startswith('SIGNED BY '):
        return {'verdict': 'REJECT', 'check': ('SIGNATURE-INVALID' if 'INVALID' in a else 'UNTRUSTED-SIGNER'), 'detail': a}
    kid = a.split(' ', 2)[2]
    if kid not in trusted:
        return {'verdict': 'REJECT', 'check': 'UNTRUSTED-SIGNER', 'detail': a}
    result, digest = verify(report_path)
    if result != 'MATCH':
        return {'verdict': 'REJECT', 'check': 'NOT-REPRODUCIBLE', 'detail': str(result)}
    need = set(policy.get('required-probes', [])) - set(str(q.get('name')) for q in report.get('probes', []))
    if need: return {'verdict': 'REJECT', 'check': 'PROBES-MISSING', 'detail': ', '.join(sorted(need))}
    names = [str(q.get("name")) for q in report.get("probes", [])]
    dupes = sorted({n for n in names if names.count(n) != 1})
    if dupes: return {"verdict": "REJECT", "check": "PROBES-DUPLICATED", "detail": ", ".join(dupes)}
    for p in report.get('probes', []):
        if p.get('status') == 'FAIL':
            return {'verdict': 'REJECT', 'check': 'PROPERTY-FAILED', 'detail': str(p.get('name')) + ' ' + str(p.get('status'))}
    rules = [str(f.get('rule')) for f in report.get('findings', [])]
    for bad in policy.get('forbidden-findings', []):
        if any(r.upper().startswith(bad.upper()) for r in rules):
            return {'verdict': 'REJECT', 'check': 'FINDING-PRESENT', 'detail': bad}
    req = [str(r) for r in policy.get('required-probes', [])]
    st = {str(q.get('name')): str(q.get('status')) for q in report.get('probes', [])}
    ok = {"PASS"}
    missed = [n for n in req if st.get(n) not in ok]
    passed = len(req) - len(missed)
    want = policy.get("min-sig-version")
    d = int(want) - int(report.get("sig_version", 1)) if want else 0
    if d == max(0, d) and d != 0: return {"verdict": "CONDITIONAL", "check": "SIG-VERSION", "detail": "sig_version " + str(report.get("sig_version", 1)) + " below " + str(want)}
    if req and not missed:
        return {'verdict': 'CLEAN', 'check': 'ALL', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req))}
    return {'verdict': 'CONDITIONAL', 'check': 'COVERAGE', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req)) + '; not passing: ' + ', '.join(missed or ['none'])}


if __name__ == "__main__" and len(sys.argv) > 3: e = evaluate(sys.argv[1], sys.argv[2], sys.argv[3]); print(json.dumps(e)); sys.exit(0 if e['verdict'] != 'REJECT' else 1)

from importlib.resources import files as pkgfiles
if __name__ == "__main__" and len(sys.argv) == 2: f = pkgfiles('mcp_authscan'); e = evaluate(sys.argv[1], str(f / 'policy-default.json'), str(f / 'keys-default.json')); print(json.dumps(e)); sys.exit(0 if e['verdict'] != 'REJECT' else 1)
