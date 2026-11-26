"""CLI regression: incomplete discovery must not downgrade assurance signing."""

import base64
import hashlib
import copy
import json
import os
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_authscan import report_verify

ROOT = Path(__file__).resolve().parents[1]
SCANNER = shutil.which("mcp-authscan")
TOKEN = "synthetic-cli-assurance-token"
CHALLENGE = "a" * 64


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, data=None):
        body = json.dumps(data).encode() if data is not None else b""
        self.send_response(status)
        if status == 401:
            self.send_header("WWW-Authenticate", 'Bearer realm="mcp-validation"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply(404)

    def do_POST(self):
        if self.path != "/mcp":
            return self.reply(404)

        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))

        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            return self.reply(401)

        req = json.loads(raw or b"{}")
        method = req.get("method")

        if method == "initialize":
            return self.reply(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "cli-assurance-regression",
                        "version": "1.0"
                    }
                }
            })

        if method == "notifications/initialized":
            return self.reply(202)

        if method == "tools/list":
            return self.reply(200, {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "result": {"tools": []}
            })

        return self.reply(200, {
            "jsonrpc": "2.0",
            "id": req.get("id"),
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        })


@pytest.mark.skipif(SCANNER is None, reason="CLI not installed")
def test_incomplete_discovery_assurance_signed_v4(tmp_path):
    key = Ed25519PrivateKey.generate()
    keyfile = tmp_path / "signing.pem"

    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))
    keyfile.chmod(0o600)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()

    target = f"http://127.0.0.1:{server.server_port}/mcp"

    env = os.environ.copy()
    env["MCPAUTHSCAN_TOKEN"] = TOKEN
    env["MCP_AUTHSCAN_SIGNING_KEY"] = str(keyfile)

    try:
        result = subprocess.run(
            [
                SCANNER, target,
                "--contact", "validation@example.com",
                "--authorized-by", "Fixture operator",
                "--auth-basis", "Owned loopback test fixture",
                "--allow-private",
                "--authentication-assurance",
                "--deployment-challenge", CHALLENGE,
                "--evidence-dir", str(tmp_path / "evidence"),
                "--sign", "--json"
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=180
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)

    assert result.stdout.strip(), result.stderr
    report = json.loads(result.stdout)

    assert result.returncode == 5, result.stderr
    assert report["completed"] is False
    assert report["sig_version"] == 4
    assert report["evidence"]["states"] == []
    assert report["provenance"]

    assurance = report["content_observed"]["authentication_assurance"]

    assert assurance["endpoint"] == target
    assert assurance["deployment_challenge"] == CHALLENGE

    assert [
        row["http_status"] for row in assurance["observations"]
    ] == [200, 401, 401, 200]

    assert [
        row["protocol_valid"] for row in assurance["observations"]
    ] == [True, False, False, True]

    from mcp_authscan.authentication_assurance import derive_verdict

    assert derive_verdict(assurance) == "VERIFIED"

    original = report_verify.signed_content(
        report, report["findings"]
    )

    signature = report["signature"]
    public_key = key.public_key()

    public_bytes = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )

    expected_key_id = hashlib.sha256(public_bytes).hexdigest()

    assert signature["alg"] == "ed25519"
    assert signature["key_id"] == expected_key_id
    assert report["key_id"] == expected_key_id

    encoded = signature["value"]
    signature_bytes = base64.urlsafe_b64decode(
        encoded + "=" * (-len(encoded) % 4)
    )

    assert len(signature_bytes) == 64

    # Verify the actual signature emitted by the scanner CLI.
    public_key.verify(signature_bytes, original)

    mutations = [
        ("deployment_challenge", "b" * 64),
        ("assessment_started_at",
         assurance["assessment_started_at"] - 1),
        ("assessment_completed_at",
         assurance["assessment_completed_at"] + 1),
    ]

    for field, value in mutations:
        altered = copy.deepcopy(report)
        altered["content_observed"]["authentication_assurance"][field] = value

        altered_content = report_verify.signed_content(
            altered, altered["findings"]
        )

        assert altered_content != original, field

        with pytest.raises(InvalidSignature):
            public_key.verify(signature_bytes, altered_content)

    # Changing observed HTTP behavior invalidates the signature.
    altered = copy.deepcopy(report)
    altered["content_observed"]["authentication_assurance"]["observations"][1]["http_status"] = 200

    with pytest.raises(InvalidSignature):
        public_key.verify(
            signature_bytes,
            report_verify.signed_content(altered, altered["findings"])
        )

    # Changing protocol validity invalidates the signature.
    altered = copy.deepcopy(report)
    altered["content_observed"]["authentication_assurance"]["observations"][1]["protocol_valid"] = True

    with pytest.raises(InvalidSignature):
        public_key.verify(
            signature_bytes,
            report_verify.signed_content(altered, altered["findings"])
        )

    # Removing authentication assurance invalidates the signature.
    altered = copy.deepcopy(report)
    del altered["content_observed"]["authentication_assurance"]

    with pytest.raises(InvalidSignature):
        public_key.verify(
            signature_bytes,
            report_verify.signed_content(altered, altered["findings"])
        )

    # A legacy signature form cannot represent this evidence.
    downgraded = copy.deepcopy(report)
    downgraded["sig_version"] = 1

    with pytest.raises(ValueError):
        report_verify.signed_content(
            downgraded, downgraded["findings"]
        )
