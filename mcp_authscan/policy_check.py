import json
import sys

from mcp_authscan.report_verify import verify, authenticity


SEVERITY_ORDER = ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
_RULE_SEPARATORS = '-_:./'


def _rule_matches(rule, bad):
    """Exact rule ID, or the ID followed by a separator (family member).
    CORS-1 matches CORS-1 and CORS-1-x, never CORS-10."""
    r, b = str(rule).strip().upper(), str(bad).strip().upper()
    return r == b or (r.startswith(b) and r[len(b)] in _RULE_SEPARATORS)


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
        if any(_rule_matches(r, bad) for r in rules):
            return {'verdict': 'REJECT', 'check': 'FINDING-PRESENT', 'detail': bad}
    floor = policy.get('fail-on')
    if floor is not None:
        if str(floor).upper() not in SEVERITY_ORDER:
            return {'verdict': 'REJECT', 'check': 'POLICY-INVALID', 'detail': 'fail-on ' + str(floor)}
        lim = SEVERITY_ORDER.index(str(floor).upper())
        for f in report.get('findings', []):
            sev = str(f.get('severity')).upper()
            if sev not in SEVERITY_ORDER or SEVERITY_ORDER.index(sev) >= lim:
                return {'verdict': 'REJECT', 'check': 'FINDING-SEVERITY', 'detail': str(f.get('rule')) + ' ' + sev}
    req = [str(r) for r in policy.get('required-probes', [])]
    st = {str(q.get('name')): str(q.get('status')) for q in report.get('probes', [])}
    ok = {"PASS"}  # required probes must PASS (654e85b); acceptable-verdicts is not read
    missed = [n for n in req if st.get(n) not in ok]
    passed = len(req) - len(missed)
    want = policy.get("min-sig-version")
    d = int(want) - int(report.get("sig_version", 1)) if want else 0
    if d > 0: return {"verdict": "REJECT", "check": "SIG-VERSION", "detail": "sig_version " + str(report.get("sig_version", 1)) + " below " + str(want)}
    scope_ops = [str(o) for o in ((policy.get('scope') or {}).get('operations') or [])]
    if req and not missed and scope_ops:
        # Only a sig_version 4 signature covers content_observed.operations (checked above by
        # authenticity()); no other report can prove which operations ran.
        signed_ops = set((report.get('content_observed') or {}).get('operations') or []) if report.get('sig_version') == 4 else None
        unproven = [o for o in scope_ops if signed_ops is None or o not in signed_ops]
        if unproven:
            why = 'operations not signed (sig_version 4 required): ' if signed_ops is None else 'scope operations not observed: '
            return {'verdict': 'CONDITIONAL', 'check': 'SCOPE', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req)) + '; ' + why + ', '.join(unproven)}
    if req and not missed:
        return {'verdict': 'CLEAN', 'check': 'ALL', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req))}
    return {'verdict': 'CONDITIONAL', 'check': 'COVERAGE', 'detail': 'hash ' + digest[:8] + ' passed ' + str(passed) + ' of ' + str(len(req)) + '; not passing: ' + ', '.join(missed or ['none'])}


if __name__ == "__main__" and len(sys.argv) > 3: e = evaluate(sys.argv[1], sys.argv[2], sys.argv[3]); print(json.dumps(e)); sys.exit(0 if e['verdict'] != 'REJECT' else 1)

from importlib.resources import files as pkgfiles
if __name__ == "__main__" and len(sys.argv) == 2: f = pkgfiles('mcp_authscan'); e = evaluate(sys.argv[1], str(f / 'policy-default.json'), str(f / 'keys-default.json')); print(json.dumps(e)); sys.exit(0 if e['verdict'] != 'REJECT' else 1)
