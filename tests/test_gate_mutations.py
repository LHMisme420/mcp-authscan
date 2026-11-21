import sys
sys.path.insert(0, "/home/lhmisme/mcp-authscan/tests")
import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp_authscan import policy_check, report_signing, report_verify
from test_gate_e2e import POLICY, bundle
def gate(tmp, key, statuses, policy=None, mutate=None):
	rp, pp, kp = bundle(tmp, key, statuses, POLICY if policy is None else policy)
	payload = json.loads(open(rp).read())
	if mutate is not None:
		mutate(payload)
	got, covered, content = report_verify.compute(payload, payload["findings"], include_bytes=True)
	payload["report_hash"] = got
	payload["signature"] = report_signing.sign_statement(key, content)
	open(rp, "w").write(json.dumps(payload))
	return policy_check.evaluate(rp, pp, kp)
def test_control_reads_clean(tmp_path):
	key = Ed25519PrivateKey.generate()
	out = gate(tmp_path, key, [("P1", "PASS"), ("P2", "PASS")])
	assert out["verdict"] == "CLEAN", out


@pytest.mark.parametrize("statuses", [
	[("P1", "PASS"), ("P1", "PASS")],
	[("P1", "pass"), ("P2", "PASS")],
	[("P2", "PASS")],
	[("P1", "FAIL"), ("P2", "PASS")],
	[("P1", ""), ("P2", "PASS")],
])
def test_manipulated_statuses_cannot_read_clean(tmp_path, statuses):
	key = Ed25519PrivateKey.generate()
	out = gate(tmp_path, key, statuses)
	assert out["verdict"] != "CLEAN", out
def test_finding_count_mismatch_cannot_be_signed(tmp_path):
	key = Ed25519PrivateKey.generate()
	with pytest.raises(ValueError):
		gate(tmp_path, key, [("P1", "PASS")], mutate=lambda p: p.update({"findings_count": 3}))
def test_tamper_without_resign_cannot_read_clean(tmp_path):
	key = Ed25519PrivateKey.generate()
	rp, pp, kp = bundle(tmp_path, key, [("P1", "PASS"), ("P2", "PASS")], POLICY)
	payload = json.loads(open(rp).read())
	payload["probes"][0]["status"] = "NOT_OBSERVED"
	open(rp, "w").write(json.dumps(payload))
	out = policy_check.evaluate(rp, pp, kp)
	assert out["verdict"] != "CLEAN", out


def test_form_one_report_cannot_read_clean_under_form_three_policy(tmp_path):
	key = Ed25519PrivateKey.generate()
	policy = dict(POLICY)
	policy["min-sig-version"] = 3
	out = gate(tmp_path, key, [("P1", "PASS")], policy=policy)
	assert out["verdict"] != "CLEAN", out
	assert out["check"] == "SIG-VERSION", out
