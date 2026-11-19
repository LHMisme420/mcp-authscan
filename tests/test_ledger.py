"""boundary-ledger-v1: append-only, one per target and access class; signed rows."""
import base64
import copy
import json
from functools import partial

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan.evidence import ledger
from mcp_authscan.evidence.delta import delta_from_ledger
from mcp_authscan.evidence.ledger import (
    SIGNED,
    UNSIGNED,
    append_entry,
    append_observation,
    attestation_status,
    commit_all,
    make_header,
    open_ledger,
    read_ledger,
    verify_ledger,
)
from mcp_authscan.evidence.state import build_state, compute_state_id
from mcp_authscan.report_signing import sign_statement

TARGET = "https://mcp.example.com/mcp"
H1, H2, H3 = "1" * 64, "2" * 64, "3" * 64
KEY = Ed25519PrivateKey.generate()
SIGNER = partial(sign_statement, KEY)


def _published(key):
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"key_id": sign_statement(key, b"x")["key_id"], "alg": "ed25519",
            "public_key": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")}


KEYS = [_published(KEY)]


def _surface(*tools):
    return {"instructions": "", "tools": [{"name": t} for t in tools], "prompts": [], "resources": []}


def _obs(state, target=TARGET, start="2026-11-18T20:00:00Z"):
    return {
        "schema": "observation-v1", "target": target, "state_id": compute_state_id(state), "state": dict(state),
        "observed_at": {"start": start, "end": start},
        "scanner": {"name": "mcp-authscan", "version": "t", "probe_set_version": "t"},
        "coverage": {"in_scope": 0, "pass": 0, "fail": 0, "not_observed": 0, "excluded": 0},
        "not_observed": [], "excluded": [],
    }


A = build_state(_surface("list_docs"), "anonymous")
B = build_state(_surface("list_docs", "write_doc"), "anonymous")


def test_append_chain_rows_carry_report_hash_and_signature(tmp_path):
    path = tmp_path / "anon.jsonl"
    first = append_observation(path, _obs(A), H1, SIGNER)
    second = append_observation(path, _obs(B, start="2026-11-18T21:00:00Z"), H2, SIGNER)
    assert first["previous_state_id"] is None and second["previous_state_id"] == A["state_id"]
    assert first["record"]["report_hash"] == H1 and second["record"]["report_hash"] == H2
    lines = read_ledger(path, KEYS)
    assert lines[0] == {"schema": "boundary-ledger-v1", "target": TARGET, "access_class": "anonymous"}
    assert [attestation_status(lines[0], row, KEYS) for row in lines[1:]] == [SIGNED, SIGNED]
    assert verify_ledger(lines, KEYS) == B["state_id"]


def test_record_is_outside_the_state_id(tmp_path):
    row = append_observation(tmp_path / "anon.jsonl", _obs(A), H1, SIGNER)
    assert row["state_id"] == A["state_id"]


def test_same_state_as_head_is_a_noop(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A), H1, SIGNER)
    before = path.read_text()
    assert append_observation(path, _obs(A), H2, SIGNER) is None
    assert path.read_text() == before


def test_revert_is_a_new_entry(tmp_path):
    path = tmp_path / "anon.jsonl"
    for state, h in ((A, H1), (B, H2), (A, H3)):
        append_observation(path, _obs(state), h, SIGNER)
    assert [r["state_id"] for r in read_ledger(path)[1:]] == [A["state_id"], B["state_id"], A["state_id"]]


def test_refuses_different_target(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A), H1, SIGNER)
    before = path.read_text()
    with pytest.raises(ValueError, match="target"):
        append_observation(path, _obs(B, target="https://other.example.com/mcp"), H2, SIGNER)
    assert path.read_text() == before


def test_refuses_different_access_class(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A), H1, SIGNER)
    before = path.read_text()
    with pytest.raises(ValueError, match="access_class"):
        append_observation(path, _obs(build_state(_surface("list_docs"), "authenticated")), H2, SIGNER)
    assert path.read_text() == before


def test_refuses_invalid_observation_and_report_hash():
    bad = _obs(A)
    bad["state_id"] = "0" * 64
    with pytest.raises(ValueError, match="state_id"):
        append_entry([make_header(TARGET, "anonymous")], bad, H1)
    with pytest.raises(ValueError, match="report_hash"):
        append_entry([make_header(TARGET, "anonymous")], _obs(A), "not-a-hash")


def _lines():
    lines = [make_header(TARGET, "anonymous")]
    for state, h in ((A, H1), (B, H2)):
        lines.append(append_entry(lines, _obs(state), h, SIGNER))
    return lines


@pytest.mark.parametrize("tamper, where", [
    (lambda ls: ls[1].update(tools=["delete_doc"]), "line 2"),
    (lambda ls: ls[2].update(previous_state_id=None), "line 3"),
    (lambda ls: ls.insert(1, ls.pop(2)), "line 2"),
    (lambda ls: ls.append(copy.deepcopy(ls[2])), "line 4"),
    (lambda ls: ls[0].update(access_class="authenticated"), "line 2"),
    (lambda ls: ls[0].update(target="HTTPS://MCP.example.com/mcp"), "line 1"),
    (lambda ls: ls.pop(0), "line 1"),
    (lambda ls: ls[1].pop("record"), "line 2"),
    (lambda ls: ls[1]["record"].update(report_hash="nope"), "line 2"),
    (lambda ls: ls[2]["record"].update(report_hash=H3), "line 3: attestation SIGNATURE INVALID"),
    (lambda ls: ls[1]["record"]["observed_at"].update(start="2000-01-01T00:00:00Z"),
     "line 2: attestation SIGNATURE INVALID"),
])
def test_offline_verification_detects_tampering(tamper, where):
    lines = _lines()
    assert verify_ledger(lines, KEYS) == B["state_id"]
    tamper(lines)
    with pytest.raises(ValueError, match=where):
        verify_ledger(lines, KEYS)


def test_unknown_signing_key_fails_verification_with_keys():
    with pytest.raises(ValueError, match="UNKNOWN KEY"):
        verify_ledger(_lines(), [_published(Ed25519PrivateKey.generate())])


def test_truncation_is_not_detected_by_design():
    # boundary-ledger-v1 §5: cutting rows off the end leaves a valid ledger.
    assert verify_ledger(_lines()[:-1], KEYS) == A["state_id"]


def test_all_or_nothing_across_ledgers(tmp_path, monkeypatch):
    anon, auth = tmp_path / "anon.jsonl", tmp_path / "auth.jsonl"
    p1 = open_ledger(anon, _obs(A))
    p2 = open_ledger(auth, _obs(build_state(_surface("list_docs"), "authenticated")))
    p1.prepare(H1, SIGNER)
    p2.prepare(H1, SIGNER)
    real_write = ledger.PendingAppend._write_tmp

    def fail_second(self):
        if self is p2:
            raise OSError("disk full")
        real_write(self)
    monkeypatch.setattr(ledger.PendingAppend, "_write_tmp", fail_second)
    with pytest.raises(OSError):
        commit_all([p1, p2])
    assert not anon.exists() and not auth.exists()              # neither row landed
    assert [p.name for p in tmp_path.iterdir() if ".tmp." in p.name] == []


def test_failed_rename_leaves_previous_ledger_intact(tmp_path, monkeypatch):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A), H1, SIGNER)
    before = path.read_bytes()

    def boom(*a):
        raise OSError("disk full")
    monkeypatch.setattr(ledger.os, "replace", boom)
    with pytest.raises(OSError):
        append_observation(path, _obs(B), H2, SIGNER)
    assert path.read_bytes() == before
    assert [p.name for p in tmp_path.iterdir() if ".tmp." in p.name] == []


# ---- a delta from the ledger needs a signed head row ------------------------------

def _ledger_with(head_signer):
    lines = [make_header(TARGET, "anonymous")]
    lines.append(append_entry(lines, _obs(A), H1, head_signer))
    return lines


def test_signed_head_satisfies_a_delta():
    d = delta_from_ledger(_ledger_with(SIGNER), _obs(B, start="2026-11-18T21:00:00Z"), KEYS)
    assert (d["classification"], d["tools"]["added"]) == ("AUTHORIZATION_REGRESSION", ["write_doc"])
    assert d["from_state_id"] == A["state_id"]


def test_unsigned_head_cannot_satisfy_a_delta():
    lines = _ledger_with(None)
    assert attestation_status(lines[0], lines[1], KEYS) == UNSIGNED
    with pytest.raises(ValueError, match="UNSIGNED; only a signed row"):
        delta_from_ledger(lines, _obs(B, start="2026-11-18T21:00:00Z"), KEYS)


def test_head_signed_by_unpublished_key_cannot_satisfy_a_delta():
    other = partial(sign_statement, Ed25519PrivateKey.generate())
    with pytest.raises(ValueError, match="UNKNOWN KEY"):
        delta_from_ledger(_ledger_with(other), _obs(B, start="2026-11-18T21:00:00Z"), KEYS)


@pytest.mark.parametrize("curr, match", [
    (lambda: _obs(B, target="https://other.example.com/mcp", start="2026-11-18T21:00:00Z"), "target"),
    (lambda: _obs(build_state(_surface("x"), "authenticated"), start="2026-11-18T21:00:00Z"), "access_class"),
    (lambda: _obs(B, start="2026-11-18T19:00:00Z"), "observed_at"),
])
def test_delta_from_ledger_refusals(curr, match):
    with pytest.raises(ValueError, match=match):
        delta_from_ledger(_ledger_with(SIGNER), curr(), KEYS)


def test_file_is_jsonl_header_first(tmp_path):
    path = tmp_path / "anon.jsonl"
    append_observation(path, _obs(A), H1, SIGNER)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert rows[0]["schema"] == "boundary-ledger-v1" and rows[1]["record"]["report_hash"] == H1
