"""No credential, and no signing key, in anything a --sign or --acquire-token run produces.

tests/test_no_token_in_output.py covers a default scan's stdout, stderr and report formats.
The two paths that carry credentials and evidence binding were not covered end to end:
--sign with the ledger, and --acquire-token. Each test here runs the real CLI against the local
fixture, makes sure the path actually ran (signed report, ledger rows, an acquired token), then
searches stdout, stderr and every file the run wrote (report, ledger, evidence) for every
credential the fixture issued or the operator supplied, and for the private signing key.
"""
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_probes_pkce_redirect import ROOT, fixture

CONTACT = "scanner-test@example.invalid"


def _key(tmp):
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    pem = k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8, s.NoEncryption())
    raw = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    path = tmp / "key.pem"
    path.write_bytes(pem)
    body = b"".join(l for l in pem.splitlines() if not l.startswith(b"-----"))
    # Every way the private key could be written out: PEM body, raw seed as hex and base64.
    return path, [body.decode(), raw.hex(), base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode().rstrip("=")]


def _run(tmp, base, extra, env_extra, runner_pre=""):
    run_dir = tmp / "run"
    run_dir.mkdir()
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MCPAUTHSCAN_", "MCP_AUTHSCAN_"))}
    env.update(env_extra, PYTHONPATH=str(ROOT))
    runner = runner_pre + "import sys; from mcp_authscan.cli_wrapper import main; sys.exit(main())"
    p = subprocess.run([sys.executable, "-c", runner, base + "/mcp", "--allow-private",
                        "--authorized-by", "X", "--auth-basis", "local fixture", "--contact", CONTACT,
                        "--json", "--sign", "--output", str(run_dir / "signed.json"), *extra],
                       cwd=str(run_dir), env=env, capture_output=True, text=True, timeout=180,
                       stdin=subprocess.DEVNULL)
    return p, run_dir


def _everything(p, run_dir, ledger):
    blobs = {"stdout": p.stdout.encode(), "stderr": p.stderr.encode()}
    for root in (run_dir, ledger):
        for f in Path(root).rglob("*"):
            if f.is_file():
                blobs[str(f.relative_to(root.parent))] = f.read_bytes()
    return blobs


def _assert_absent(blobs, secrets):
    hits = {name: s for name, data in blobs.items() for s in secrets if s and s.encode() in data}
    assert hits == {}, hits


def _assert_signed_and_ledgered(p, run_dir, ledger):
    report = json.loads((run_dir / "signed.json").read_text())
    assert report.get("signature") and report.get("sig_version"), "report was not signed"
    rows = [l for f in Path(ledger).rglob("*.jsonl") for l in f.read_text().splitlines() if l.strip()]
    assert rows, "no ledger row written"
    return report


def test_sign_with_ledger_leaks_no_token_secret_or_key(tmp_path):
    key, key_forms = _key(tmp_path)
    ledger = tmp_path / "ledger"
    with fixture(MISBEHAVE="1") as base:
        p, run_dir = _run(tmp_path, base, [], {
            "MCPAUTHSCAN_CLIENT_ID": "fixture-client", "MCPAUTHSCAN_CLIENT_SECRET": "fixture-secret",
            "MCPAUTHSCAN_REDIRECT_URI": base + "/cb",
            "MCP_AUTHSCAN_SIGNING_KEY": str(key), "MCP_AUTHSCAN_LEDGER_DIR": str(ledger)})
    assert p.returncode == 1, p.stderr[-1500:]
    report = _assert_signed_and_ledgered(p, run_dir, ledger)
    probes = {r["name"]: r["status"] for r in report["probes"]}
    assert probes["token-cors"] == "FAIL" and probes["password-grant"] == "FAIL"  # tokens were issued
    _assert_absent(_everything(p, run_dir, ledger),
                   ["fixture-token", "fixture-password-token", "fixture-secret"] + key_forms)


ACQUIRE_PRE = (
    "import tests.test_token_cors_acquired as T, mcp_authscan.oauth_probes_v2 as P\n"
    "P._prompt_for_redirect = T.Browser()\n"
)


def test_acquire_token_with_sign_leaks_no_token_code_secret_or_key(tmp_path):
    key, key_forms = _key(tmp_path)
    ledger = tmp_path / "ledger"
    with fixture(TOKEN_CORS="wildcard") as base:
        p, run_dir = _run(tmp_path, base, ["--acquire-token"], {
            "MCP_AUTHSCAN_SIGNING_KEY": str(key), "MCP_AUTHSCAN_LEDGER_DIR": str(ledger)},
            runner_pre=ACQUIRE_PRE)
    report = _assert_signed_and_ledgered(p, run_dir, ledger)
    tc = next(r for r in report["probes"] if r["name"] == "token-cors")
    assert "access token obtained" in (tc.get("detail") or ""), (tc, p.stderr[-1500:])
    _assert_absent(_everything(p, run_dir, ledger),
                   ["fixture-acquired", "fixture-code", "fixture-rat", "fixture-secret"] + key_forms)
