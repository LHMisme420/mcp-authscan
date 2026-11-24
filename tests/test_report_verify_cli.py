"""report_verify CLI: one line per report, and unreadable reports never crash it."""
from mcp_authscan import report_verify


def test_missing_report_prints_not_reproducible(tmp_path, capsys):
    rc = report_verify.main([str(tmp_path / "absent.json")])
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert len(lines) == 1 and lines[0].startswith("NOT REPRODUCIBLE "), lines


def test_corrupt_report_prints_not_reproducible(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    rc = report_verify.main([str(bad)])
    lines = capsys.readouterr().out.splitlines()
    assert rc == 1
    assert len(lines) == 1 and lines[0].startswith("NOT REPRODUCIBLE "), lines


def test_exactly_one_line_per_report(tmp_path, capsys):
    report_verify.main([str(tmp_path / "a.json"), str(tmp_path / "b.json")])
    assert len(capsys.readouterr().out.splitlines()) == 2


def test_unsigned_probe_edit_is_labelled_not_verified(tmp_path, capsys):
    """report_hash does not cover probe statuses: a key-free edit still reads MATCH,
    so the line must say the probes were not verified."""
    import json
    import sys
    sys.path.insert(0, "/home/lhmisme/mcp-authscan/tests")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from test_gate_e2e import POLICY, bundle
    rp, _, _ = bundle(tmp_path, Ed25519PrivateKey.generate(), [("P1", "NOT_OBSERVED")], POLICY)
    payload = json.loads(open(rp).read())
    payload["probes"][0]["status"] = "PASS"
    open(rp, "w").write(json.dumps(payload))
    report_verify.main([rp])
    line = capsys.readouterr().out.splitlines()[0]
    assert line.startswith("MATCH "), line
    assert "[probes: NOT VERIFIED" in line, line


def test_require_signature_always_unsigned_nonzero_signed_zero(tmp_path):
    """D1: exit is the engine's verdict and a signature is required always. With --keys a
    trusted signed report exits 0; an unsigned one exits nonzero; a signed report with no
    --keys exits nonzero too (no hash-only fail-open door)."""
    import json, sys as _sys
    _sys.path.insert(0, "tests")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from test_gate_e2e import build, pub
    key = Ed25519PrivateKey.generate()
    signed = build(key, [("P1", "PASS")]); kid = signed["signature"]["key_id"]
    rp = tmp_path / "signed.json"; rp.write_text(json.dumps(signed))
    kp = tmp_path / "keys.json"
    kp.write_text(json.dumps([{"key_id": kid, "alg": "ed25519", "public_key": pub(key)}]))
    assert report_verify.main(["--keys", str(kp), str(rp)]) == 0
    assert report_verify.main([str(rp)]) != 0
    unsigned = dict(signed); unsigned.pop("signature", None); unsigned.pop("sig_version", None)
    up = tmp_path / "unsigned.json"; up.write_text(json.dumps(unsigned))
    assert report_verify.main(["--keys", str(kp), str(up)]) != 0
