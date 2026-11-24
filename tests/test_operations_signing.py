"""sig_version 4: content_observed.operations is signed, and CLEAN under a declared
scope requires every scope operation in that signed list."""
import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mcp_authscan import content_probe, policy_check, report_signing, report_verify as rv  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "compat" / "signed-schema3-main-1a7d08c.json"
ALL = ["initialize", "tools/list", "prompts/list", "resources/list"]


def _report(ops, session=True):
    r = json.loads(FIX.read_text())
    for p in r.get("probes") or []:
        p["status"] = "PASS"
    if "provenance" not in r:
        r["provenance"] = {"tool_version": "test", "tool_manifest": "0" * 64}
    if "evidence" not in r:
        from test_evidence_signing import EV
        r["evidence"] = EV
    if ops is not None:
        r["content_observed"] = {"version": "t", "session_established": session, "operations": list(ops),
                                 "inspected": {}, "reasons": []}
    return r


def _sign(r, key, version):
    r["sig_version"] = version
    assert report_signing.sign_report(r, rv.signed_content(r, r.get("findings") or []), key=key)
    return r


def _bundle(tmp_path, r, key):
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = report_signing.sign_statement(key, b"t")["key_id"]
    policy = {"trusted-signers": [{"key-id": kid}], "required-probes": [p["name"] for p in r.get("probes") or []],
              "forbidden-findings": [], "min-sig-version": 3, "scope": {"operations": list(ALL)}}
    pp = tmp_path / "policy.json"; pp.write_text(json.dumps(policy))
    kp = tmp_path / "keys.json"
    kp.write_text(json.dumps([{"key_id": kid, "alg": "ed25519",
                               "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}]))
    rp = tmp_path / "report.json"; rp.write_text(json.dumps(r))
    return str(rp), str(pp), str(kp)


def _gate(tmp_path, r, key):
    return policy_check.evaluate(*_bundle(tmp_path, r, key))


def test_v4_with_every_scope_operation_is_clean(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = _gate(tmp_path, _sign(_report(ALL), key, 4), key)
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SEVERITY"), out  # incidental HIGH finding, no fail-on -> blocked from CLEAN
    assert "HIGH" in out["detail"], out


def test_v4_missing_operation_is_named(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = _gate(tmp_path, _sign(_report([o for o in ALL if o != "prompts/list"]), key, 4), key)
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SCOPE"), out
    assert "not observed: prompts/list" in out["detail"], out


def test_v4_operation_added_after_signing_breaks_signature(tmp_path):
    key = Ed25519PrivateKey.generate()
    r = _sign(_report([o for o in ALL if o != "prompts/list"]), key, 4)
    r["content_observed"]["operations"].append("prompts/list")
    out = _gate(tmp_path, r, key)
    assert (out["verdict"], out["check"]) == ("REJECT", "SIGNATURE-INVALID"), out


def test_v3_cannot_sign_operations():
    with pytest.raises(ValueError, match="sig_version: 3 does not cover"):
        r = dict(_report(ALL), sig_version=3)
        rv.signed_content(r, r.get("findings") or [])


def test_operations_injected_into_a_v3_report_break_its_signature(tmp_path):
    key = Ed25519PrivateKey.generate()
    r = _sign(_report(None), key, 3)
    r["content_observed"] = {"version": "t", "session_established": True, "operations": list(ALL), "inspected": {}, "reasons": []}
    out = _gate(tmp_path, r, key)
    assert (out["verdict"], out["check"]) == ("REJECT", "SIGNATURE-INVALID"), out


def test_v3_under_a_declared_scope_says_v4_is_required(tmp_path):
    key = Ed25519PrivateKey.generate()
    out = _gate(tmp_path, _sign(_report(None), key, 3), key)
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SCOPE"), out
    assert "sig_version 4 required" in out["detail"], out


def test_sig_version_for_picks_4_only_with_operations():
    assert rv.sig_version_for(_report(ALL)) == 4
    assert rv.sig_version_for(_report(None)) == 3


@pytest.mark.parametrize("ops,session", [
    (["tools/list"], True),               # session established but initialize missing
    (["initialize"], False),              # initialize listed without a session
    (["initialize", "bogus/list"], True), # unknown operation
    (["initialize", "initialize"], True), # duplicate
])
def test_inconsistent_operations_are_rejected(ops, session):
    with pytest.raises(ValueError):
        rv.operations_binding({"content_observed": {"operations": ops, "session_established": session}})


def test_cli_labels_v4_probes_and_operations_signed(tmp_path, capsys):
    key = Ed25519PrivateKey.generate()
    rp, _, kp = _bundle(tmp_path, _sign(_report(ALL), key, 4), key)
    rv.main(["--keys", kp, rp])
    line = capsys.readouterr().out.splitlines()[0]
    assert "[probes: signed]" in line and "[operations: signed]" in line, line


def test_observe_records_successful_operations(monkeypatch):
    responses = {"tools/list": {"result": {"tools": [{"name": "t", "description": "d"}]}},
                 "prompts/list": {"error": {"code": -32601}},
                 "resources/list": {"result": {"resources": []}}}
    monkeypatch.setattr(content_probe.mcp_session, "open_session", lambda *a, **k: {"established": True, "session_id": "s"})
    monkeypatch.setattr(content_probe.mcp_session, "_post_jsonrpc", lambda endpoint, payload, *a, **k: (200, {}, payload["method"]))
    monkeypatch.setattr(content_probe, "_parse", lambda status, hdrs, raw: responses[raw])
    out = content_probe.observe("https://mcp.example.invalid/mcp")
    assert out["session_established"] is True
    assert out["operations"] == ["initialize", "tools/list", "resources/list"], out


def test_observe_without_a_session_records_no_operations(monkeypatch):
    monkeypatch.setattr(content_probe.mcp_session, "open_session", lambda *a, **k: {"established": False, "reason": "HTTP 401"})
    out = content_probe.observe("https://mcp.example.invalid/mcp")
    assert out["session_established"] is False and out["operations"] == [], out


# manifest pin (require-manifest-pin)

UNPINNED = {"tool_version": "0.0.0-unpinned", "tool_manifest": "0" * 64}


def _require_pin(pp):
    pol = json.loads(Path(pp).read_text())
    pol["require-manifest-pin"] = True
    Path(pp).write_text(json.dumps(pol))


def test_unpinned_manifest_is_rejected_by_name(tmp_path):
    key = Ed25519PrivateKey.generate()
    r = _report(ALL); r["provenance"] = dict(UNPINNED)
    rp, pp, kp = _bundle(tmp_path, _sign(r, key, 4), key)
    _require_pin(pp)
    out = policy_check.evaluate(rp, pp, kp)
    assert (out["verdict"], out["check"]) == ("REJECT", "MANIFEST-PIN"), out
    assert out["detail"].startswith("VERSION NOT PINNED"), out


def test_pinned_manifest_passes(tmp_path, monkeypatch):
    from mcp_authscan import releases
    monkeypatch.setitem(releases.MANIFEST_HASHES, UNPINNED["tool_version"], UNPINNED["tool_manifest"])
    key = Ed25519PrivateKey.generate()
    r = _report(ALL); r["provenance"] = dict(UNPINNED)
    rp, pp, kp = _bundle(tmp_path, _sign(r, key, 4), key)
    _require_pin(pp)
    out = policy_check.evaluate(rp, pp, kp)
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SEVERITY"), out  # incidental HIGH finding, no fail-on -> blocked from CLEAN
    assert "HIGH" in out["detail"], out


def test_pin_not_required_without_the_key(tmp_path):
    key = Ed25519PrivateKey.generate()
    r = _report(ALL); r["provenance"] = dict(UNPINNED)
    out = _gate(tmp_path, _sign(r, key, 4), key)
    assert out["check"] != "MANIFEST-PIN", out


SELF = {"tool_version": "0.0.0-self", "tool_manifest": "a" * 64}


def _as_installed(monkeypatch):
    import mcp_authscan
    from mcp_authscan import report_verify
    monkeypatch.setattr(mcp_authscan, "__version__", SELF["tool_version"])
    monkeypatch.setattr(report_verify, "build_provenance", lambda: dict(SELF))


def test_same_version_report_matching_installed_manifest_passes(tmp_path, monkeypatch):
    _as_installed(monkeypatch)
    key = Ed25519PrivateKey.generate()
    r = _report(ALL); r["provenance"] = dict(SELF)
    rp, pp, kp = _bundle(tmp_path, _sign(r, key, 4), key)
    _require_pin(pp)
    out = policy_check.evaluate(rp, pp, kp)
    assert (out["verdict"], out["check"]) == ("CONDITIONAL", "SEVERITY"), out  # incidental HIGH finding, no fail-on -> blocked from CLEAN
    assert "HIGH" in out["detail"], out


def test_same_version_report_with_another_manifest_is_rejected(tmp_path, monkeypatch):
    _as_installed(monkeypatch)
    key = Ed25519PrivateKey.generate()
    r = _report(ALL); r["provenance"] = {"tool_version": SELF["tool_version"], "tool_manifest": "b" * 64}
    rp, pp, kp = _bundle(tmp_path, _sign(r, key, 4), key)
    _require_pin(pp)
    out = policy_check.evaluate(rp, pp, kp)
    assert (out["verdict"], out["check"]) == ("REJECT", "MANIFEST-PIN"), out
    assert out["detail"].startswith("MANIFEST NOT INSTALLED"), out
