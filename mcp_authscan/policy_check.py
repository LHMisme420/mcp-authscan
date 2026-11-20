import json
import sys

from mcp_authscan.report_verify import verify, authenticity


def evaluate(report_path, policy_path, keys_path):
	policy = json.load(open(policy_path))
	report = json.load(open(report_path))
	keys = json.load(open(keys_path)) if isinstance(keys_path, str) else keys_path
	trusted = {k.get('key-id') for k in policy.get('trusted-signers', [])}
	a = authenticity(report, keys)
	if not a.startswith('SIGNED BY '):
		return {'verdict': 'REJECT', 'check': ('SIGNATURE-INVALID' if 'INVALID' in a else 'UNTRUSTED-SIGNER'), 'detail': a}
	kid = a.split(' ', 2)[2]
	if kid not in trusted:
		return {'verdict': 'REJECT', 'check': 'UNTRUSTED-SIGNER', 'detail': a}
	result, digest = verify(report_path)
	if result != 'MATCH':
		return {'verdict': 'REJECT', 'check': 'NOT-REPRODUCIBLE', 'detail': str(result)}
	accept = set(policy.get('acceptable-verdicts', []))
	for p in report.get('probes', []):
		if p.get('status') not in accept:
			return {'verdict': 'REJECT', 'check': 'PROPERTY-FAILED', 'detail': str(p.get('name')) + ' ' + str(p.get('status'))}
	rules = [str(f.get('rule')) for f in report.get('findings', [])]
	for bad in policy.get('forbidden-findings', []):
		if any(r.upper().startswith(bad.upper()) for r in rules):
			return {'verdict': 'REJECT', 'check': 'FINDING-PRESENT', 'detail': bad}
	return {'verdict': 'ACCEPT', 'check': 'ALL', 'detail': 'hash ' + digest[:8] + ' probes ' + str(len(report.get('probes') or []))}


if len(sys.argv) > 3: print(json.dumps(evaluate(sys.argv[1], sys.argv[2], sys.argv[3])))
