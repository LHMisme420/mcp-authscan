"""verify-mcp/server.py, run as the MCP client runs it: a subprocess spoken to over stdio.

Covers the review of 2026-11-19: the trusted keyring belongs to the operator, not the caller;
the report path cannot leave the evidence directory by symlink, '..' or a swapped directory;
malformed requests get JSON-RPC errors and the server keeps serving; error text never echoes
exception messages, paths or file contents.
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "verify-mcp" / "server.py"

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import serialization as s  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from mcp_authscan import report_signing, report_verify  # noqa: E402


def _keyentry(key):
    pub = key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
    return {"key_id": hashlib.sha256(pub).hexdigest(), "alg": "ed25519",
            "public_key": base64.urlsafe_b64encode(pub).decode().rstrip("=")}


FIXTURE_REPORT = ROOT / "tests" / "fixtures" / "compat" / "signed-schema3-main-1a7d08c.json"


def _report(key):
    """The committed schema-3 compat report (its hash verifies MATCH), re-signed by `key`."""
    payload = json.loads(FIXTURE_REPORT.read_text())
    for k in ("signature", "key_id", "sig_version"):
        payload.pop(k, None)
    assert report_verify.verify_payload(payload)[0] == "MATCH"
    content = report_verify.signed_content(payload, payload.get("findings") or [])
    report_signing.sign_report(payload, content, key=key)
    return payload


@pytest.fixture
def env(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    operator, attacker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    (evidence / "operator.json").write_text(json.dumps(_report(operator)))
    (evidence / "attacker.json").write_text(json.dumps(_report(attacker)))
    (outside / "operator-keys.json").write_text(json.dumps([_keyentry(operator)]))
    (outside / "attacker-keys.json").write_text(json.dumps([_keyentry(attacker)]))
    (outside / "outside-report.json").write_text(json.dumps(_report(operator)))
    return {"tmp": tmp_path, "evidence": evidence, "outside": outside,
            "operator_id": _keyentry(operator)["key_id"], "attacker_id": _keyentry(attacker)["key_id"]}


def run(env, lines, keyring="operator"):
    e = {k: v for k, v in os.environ.items() if not k.startswith("MCP_AUTHSCAN_")}
    e.update(PYTHONPATH=str(ROOT), MCP_AUTHSCAN_EVIDENCE=str(env["evidence"]))
    if keyring:
        e["MCP_AUTHSCAN_TRUSTED_KEYS"] = str(env["outside"] / ("%s-keys.json" % keyring)) \
            if keyring in ("operator", "attacker") else keyring
    p = subprocess.run([sys.executable, str(SERVER)], input="".join(l + "\n" for l in lines),
                       capture_output=True, text=True, env=e, timeout=60)
    msgs = [json.loads(l) for l in p.stdout.splitlines()]
    return p, msgs


def call(i, args):
    return json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                       "params": {"name": "verify", "arguments": args}})


def text_of(msg):
    return msg["result"]["content"][0]["text"]


def one(env, args, keyring="operator"):
    p, msgs = run(env, [call(1, args)], keyring)
    assert p.returncode == 0, p.stderr
    return text_of(msgs[0])


# --- trust: the operator's keyring, never the caller's

def test_operator_key_is_trusted(env):
    t = one(env, {"path": str(env["evidence"] / "operator.json")})
    assert "VERDICT MATCH" in t and "SIGNATURE SIGNED BY " + env["operator_id"] in t


def test_report_signed_by_another_key_is_unknown_not_trusted(env):
    t = one(env, {"path": str(env["evidence"] / "attacker.json")})
    assert "VERDICT MATCH" in t and "SIGNATURE UNKNOWN KEY" in t


def test_caller_cannot_supply_keys(env):
    t = one(env, {"path": str(env["evidence"] / "attacker.json"), "keys": str(env["outside"] / "attacker-keys.json")})
    assert t.startswith("ERROR keys are not accepted from the caller")
    assert env["attacker_id"] not in t and "SIGNED BY" not in t


def test_tool_schema_offers_no_keys_argument(env):
    _, msgs = run(env, [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})])
    schema = msgs[0]["result"]["tools"][0]["inputSchema"]
    assert set(schema["properties"]) == {"path"} and schema["additionalProperties"] is False


def test_no_keyring_means_not_checked(env):
    t = one(env, {"path": str(env["evidence"] / "operator.json")}, keyring=None)
    assert "SIGNATURE NOT CHECKED (no trusted keyring configured by the operator)" in t


@pytest.mark.parametrize("content", ["not json", "{}", "[]", '[{"alg": "ed25519", "key_id": "00", "public_key": "AA"}]'])
def test_unusable_keyring_refuses_to_start(env, content):
    bad = env["outside"] / "bad-keys.json"
    bad.write_text(content)
    p, msgs = run(env, [call(1, {"path": str(env["evidence"] / "operator.json")})], keyring=str(bad))
    assert p.returncode == 2 and msgs == []
    assert str(bad) not in p.stderr


# --- confinement

def test_outside_path_refused(env):
    t = one(env, {"path": str(env["outside"] / "outside-report.json")})
    assert t == "ERROR report must be a file inside the evidence directory"


def test_dotdot_refused(env):
    t = one(env, {"path": str(env["evidence"]) + "/../outside/outside-report.json"})
    assert t.startswith("ERROR report must be")


def test_symlinked_file_refused(env):
    (env["evidence"] / "link.json").symlink_to(env["outside"] / "outside-report.json")
    assert one(env, {"path": str(env["evidence"] / "link.json")}).startswith("ERROR report must be")


def test_symlinked_directory_refused(env):
    # A directory inside the evidence dir that is (or is swapped for) a symlink to outside: the
    # O_NOFOLLOW walk will not traverse it, whenever the swap happens.
    (env["evidence"] / "sub").symlink_to(env["outside"], target_is_directory=True)
    assert one(env, {"path": str(env["evidence"] / "sub" / "outside-report.json")}).startswith("ERROR report must be")


def test_real_subdirectory_allowed(env):
    (env["evidence"] / "runs").mkdir()
    (env["evidence"] / "runs" / "r.json").write_text((env["evidence"] / "operator.json").read_text())
    assert "SIGNED BY" in one(env, {"path": str(env["evidence"] / "runs" / "r.json")})


def test_fifo_refused_without_hanging(env):
    os.mkfifo(env["evidence"] / "pipe.json")
    assert one(env, {"path": str(env["evidence"] / "pipe.json")}).startswith("ERROR")


def test_oversize_refused(env):
    (env["evidence"] / "big.json").write_bytes(b" " * (5 * 1024 * 1024 + 1))
    assert one(env, {"path": str(env["evidence"] / "big.json")}) == "ERROR file is larger than 5242880 bytes"


# --- malformed input: errors, and the server keeps serving

@pytest.mark.parametrize("line,code", [
    ("{oops", -32700),
    ("[]", -32600),
    ('"just a string"', -32600),
    (json.dumps({"jsonrpc": "2.0", "id": 7, "method": 5}), -32600),
    (json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": "x"}), -32600),
    (json.dumps({"jsonrpc": "2.0", "id": 7, "method": "nope"}), -32601),
])
def test_malformed_lines_get_errors_and_serving_continues(env, line, code):
    p, msgs = run(env, [line, json.dumps({"jsonrpc": "2.0", "id": 99, "method": "tools/list"})])
    assert p.returncode == 0, p.stderr
    assert msgs[0]["error"]["code"] == code
    assert msgs[-1]["id"] == 99 and "tools" in msgs[-1]["result"]


@pytest.mark.parametrize("args,expect", [
    ("x", "ERROR arguments must be an object"),
    ({"path": 5}, "ERROR path must be a non-empty string"),
    ({}, "ERROR path must be a non-empty string"),
    ({"path": "a", "extra": 1}, "ERROR unknown argument"),
])
def test_bad_arguments_are_refused_plainly(env, args, expect):
    assert one(env, args) == expect


# --- sanitized errors

def test_errors_do_not_echo_paths_or_parser_messages(env):
    (env["evidence"] / "bad.json").write_text("{not json")
    lines = [call(1, {"path": str(env["evidence"] / "bad.json")}),
             call(2, {"path": str(env["evidence"] / "missing.json")}),
             call(3, {"path": str(env["outside"] / "secret")})]
    p, msgs = run(env, lines)
    texts = [text_of(m) for m in msgs]
    assert texts[0] == "ERROR report is not valid UTF-8 JSON"
    for t in texts:
        assert str(env["tmp"]) not in t and "Errno" not in t and "Expecting" not in t
    assert str(env["tmp"]) not in p.stderr
