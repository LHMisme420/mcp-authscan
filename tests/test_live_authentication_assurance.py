"""Live loopback authentication contrast and signed deployment enforcement."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from mcp_authscan import (
    authentication_assurance,
    report_signing,
    report_verify,
)

from .test_gate_e2e import POLICY, bundle_v3
from .test_gate_authentication_assurance import _run


TOKEN = "local-assurance-test-only"


class MCPHandler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(size))

        self.server.observed_requests += 1

        if self.path != "/mcp":
            self.send_response(404)
            self.end_headers()
            return

        if request.get("method") != "initialize":
            self.send_response(400)
            self.end_headers()
            return

        authorization = self.headers.get("Authorization")

        accepted = (
            authorization == "Bearer " + TOKEN
            or (
                self.server.regressed
                and authorization is None
            )
        )

        if not accepted:
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        result = {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {
                "protocolVersion": request["params"]["protocolVersion"],
                "capabilities": {},
                "serverInfo": {
                    "name": "authscan-live-fixture",
                    "version": "1.0",
                },
            },
        }

        body = json.dumps(result).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_live_authentication_lifecycle(tmp_path):

    server = ThreadingHTTPServer(
        ("127.0.0.1", 0),
        MCPHandler,
    )

    server.regressed = False
    server.observed_requests = 0

    worker = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )

    worker.start()

    endpoint = (
        f"http://127.0.0.1:{server.server_port}/mcp"
    )

    key = Ed25519PrivateKey.generate()

    policy = {
        **POLICY,
        "min-sig-version": 4,
        "verified-authentication-required": True,
    }

    results = []
    signer_ids = set()
    policies = set()

    try:
        for state, regressed, expected, expected_code in (
            ("SECURE", False, "VERIFIED", 0),
            ("REGRESSED", True, "CONTRADICTED", 1),
            ("REMEDIATED", False, "VERIFIED", 0),
        ):
            server.regressed = regressed

            evidence = authentication_assurance.observe(
                endpoint,
                token=TOKEN,
                allow_private=True,
                allowed_hosts=["127.0.0.1"],
            )

            verdict = authentication_assurance.derive_verdict(
                evidence
            )

            assert verdict == expected, evidence

            directory = tmp_path / state.lower()
            directory.mkdir()

            paths = bundle_v3(
                directory,
                key,
                [("P1", "PASS")],
                policy,
            )

            rp, pp, kp = map(Path, paths)

            report = json.loads(rp.read_text())
            report["target"] = endpoint
            report["sig_version"] = 4

            report["content_observed"] = {
                "version": "live-test",
                "credential_context": "credentialed",
                "session_established": False,
                "operations": [],
                "inspected": {},
                "reasons": [],
                "authentication_assurance": evidence,
            }

            report["report_hash"] = report_verify.compute(
                report,
                report["findings"],
            )[0]

            report["signature"] = report_signing.sign_statement(
                key,
                report_verify.signed_content(
                    report,
                    report["findings"],
                ),
            )

            signer_ids.add(report["signature"]["key_id"])
            policies.add(pp.read_text())

            rp.write_text(json.dumps(report, indent=2))

            assert TOKEN not in rp.read_text()

            code, decision = _run(paths)

            assert code == expected_code, decision

            statuses = [
                row["http_status"]
                for row in evidence["observations"]
            ]

            results.append(
                (state, verdict, decision["verdict"], code)
            )

            print(
                f"\n[LIVE] {state}"
                f" | HTTP={statuses}"
                f" | ASSURANCE={verdict}"
                f" | GATE={decision['verdict']}"
                f" | EXIT={code}"
            )

        assert results == [
            ("SECURE", "VERIFIED", "CLEAN", 0),
            ("REGRESSED", "CONTRADICTED", "REJECT", 1),
            ("REMEDIATED", "VERIFIED", "CLEAN", 0),
        ]

        assert len(signer_ids) == 1
        assert len(policies) == 1
        assert server.observed_requests == 12

        print("\n[PASS] Same endpoint")
        print("[PASS] Same signing identity")
        print("[PASS] Same deployment policy")
        print("[PASS] 12 actual HTTP requests")
        print("[PASS] Secure -> Regressed -> Remediated")

    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
