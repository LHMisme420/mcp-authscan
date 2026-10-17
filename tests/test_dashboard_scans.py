import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch


_test_directory = tempfile.TemporaryDirectory(prefix="vata-dashboard-tests-")
os.environ["DB_FILE"] = os.path.join(_test_directory.name, "test.db")
os.environ["JWT_SECRET"] = "dashboard-scan-tests-only-secret"

import app as app_module
import app_full as full_app_module
from flask_jwt_extended import create_access_token
from mcp_authscan.scanner import Check, RiskLevel, ScanError
from requests import ConnectionError as RequestsConnectionError


class DashboardScanTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        with sqlite3.connect(app_module.DB_FILE) as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM scan_runs")
            conn.execute("DELETE FROM organizations")
            cursor = conn.execute(
                "INSERT INTO organizations (name, api_key) VALUES (?, ?)",
                ("scan-test-org", "scan-test-key"),
            )
            self.org_id = cursor.lastrowid
            cursor = conn.execute(
                "INSERT INTO organizations (name, api_key) VALUES (?, ?)",
                ("other-scan-test-org", "other-scan-test-key"),
            )
            self.other_org_id = cursor.lastrowid

        with app_module.app.app_context():
            self.token = create_access_token(identity=str(self.org_id))
            self.other_token = create_access_token(identity=str(self.other_org_id))
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_scan_endpoint_requires_a_jwt(self):
        response = self.client.post(
            "/api/scans/mcp", json={"target_url": "https://mcp.example.test"}
        )
        self.assertEqual(response.status_code, 401)

    def test_scan_requires_authorization_attestation(self):
        # Authenticated, valid target, but no `authorized: true` -> rejected,
        # and nothing is scanned.
        for payload in (
            {"target_url": "https://mcp.example.test"},
            {"target_url": "https://mcp.example.test", "authorized": False},
            {"target_url": "https://mcp.example.test", "authorized": "yes"},
        ):
            response = self.client.post(
                "/api/scans/mcp", json=payload, headers=self.headers)
            self.assertEqual(response.status_code, 403)
            self.assertIn("authorized", response.get_json()["error"].lower())

    def test_scan_results_are_stored_and_scoped_to_the_token_organization(self):
        checks = [
            Check(
                name="MCP Endpoint Authentication",
                description="Endpoint accepts unauthenticated requests",
                endpoint="/mcp",
                method="POST",
                risk_level=RiskLevel.CRITICAL,
                passed=False,
                details="Status: 200",
                remediation="Require authentication",
            ),
            Check(
                name="Endpoint Reachability",
                description="MCP endpoint responds",
                endpoint="*",
                method="HEAD",
                risk_level=RiskLevel.INFO,
                passed=True,
                details="HTTP 200",
                remediation="",
            ),
        ]
        with patch.object(app_module.MCPScanner, "scan", return_value=checks):
            response = self.client.post(
                "/api/scans/mcp",
                json={"target_url": "https://mcp.example.test", "authorized": True},
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual(result["scan"]["findings_count"], 1)
        self.assertEqual(result["scan"]["critical_count"], 1)
        self.assertTrue(result["scan"]["has_critical"])

        findings = self.client.get("/api/findings", headers=self.headers).get_json()["findings"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["server"], "https://mcp.example.test")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["scan_id"], result["scan"]["id"])
        self.assertEqual(
            len(self.client.get("/api/findings", headers={
                "Authorization": f"Bearer {self.other_token}"
            }).get_json()["findings"]),
            0,
        )

        scans = self.client.get("/api/scans/mcp", headers=self.headers).get_json()["scans"]
        self.assertEqual(scans[0]["status"], "completed")
        self.assertEqual(scans[0]["critical_count"], 1)
        self.assertEqual(
            len(self.client.get("/api/scans/mcp", headers={
                "Authorization": f"Bearer {self.other_token}"
            }).get_json()["scans"]),
            0,
        )

        compliance = self.client.get(
            "/api/reports/compliance", headers=self.headers
        ).get_json()
        self.assertEqual(compliance["critical_findings"], 1)
        self.assertEqual(compliance["compliance_score"], 0)

    def test_unreachable_target_is_reported_and_saved_as_failed(self):
        with patch.object(
            app_module.MCPScanner, "scan",
            side_effect=ScanError("Unable to reach any MCP endpoint."),
        ):
            response = self.client.post(
                "/api/scans/mcp",
                json={"target_url": "https://unreachable.example.test", "authorized": True},
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.get_json()["status"], "failed")
        self.assertIn("Unable to reach", response.get_json()["error"])
        scans = self.client.get("/api/scans/mcp", headers=self.headers).get_json()["scans"]
        self.assertEqual(scans[0]["status"], "failed")
        self.assertIn("Unable to reach", scans[0]["error"])
        self.assertEqual(
            self.client.get("/api/findings", headers=self.headers).get_json()["findings"],
            [],
        )

    def test_dashboard_scan_route_runs_the_scanner_against_a_local_mcp_fixture(self):
        class InsecureMCPFixture(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.respond()

            def do_GET(self):
                self.respond()

            def do_POST(self):
                self.respond()

            def respond(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), InsecureMCPFixture)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        try:
            response = self.client.post(
                "/api/scans/mcp",
                json={"target_url": f"http://127.0.0.1:{server.server_port}", "timeout": 1, "authorized": True},
                headers=self.headers,
            )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=2)

        self.assertEqual(response.status_code, 200)
        summary = response.get_json()["scan"]
        self.assertGreater(summary["critical_count"], 0)
        findings = self.client.get("/api/findings", headers=self.headers).get_json()["findings"]
        self.assertGreater(len(findings), 0)
        self.assertTrue(all(finding["server"].startswith("http://127.0.0.1:") for finding in findings))

    def test_target_and_timeout_are_validated_before_scanning(self):
        for payload in (
            {"target_url": "file:///etc/passwd"},
            {"target_url": "https://mcp.example.test", "timeout": 60},
        ):
            with self.subTest(payload=payload):
                response = self.client.post(
                    "/api/scans/mcp", json=payload, headers=self.headers
                )
                self.assertEqual(response.status_code, 400)

    def test_scanner_raises_a_clear_error_when_every_endpoint_is_unreachable(self):
        scanner = app_module.MCPScanner("https://unreachable.example.test")
        with patch.object(
            scanner.session, "head", side_effect=RequestsConnectionError("offline")
        ):
            with self.assertRaisesRegex(ScanError, "Unable to reach any MCP endpoint"):
                scanner.scan()
        self.assertFalse(scanner.checks[0].passed)


class ActiveWorkflowScanTests(unittest.TestCase):
    def setUp(self):
        self.client = full_app_module.app.test_client()
        with sqlite3.connect(full_app_module.DB_FILE) as conn:
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM scans")
            conn.execute("DELETE FROM organizations")
            cursor = conn.execute(
                "INSERT INTO organizations (name, api_key) VALUES (?, ?)",
                ("active-workflow-org", "active-workflow-test-key"),
            )
            self.org_id = cursor.lastrowid
        with full_app_module.app.app_context():
            self.token = create_access_token(identity=str(self.org_id))
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_configured_full_app_scan_contract_stores_dashboard_results(self):
        check = Check(
            name="MCP Endpoint Authentication",
            description="Endpoint accepts unauthenticated requests",
            endpoint="/mcp",
            method="POST",
            risk_level=RiskLevel.CRITICAL,
            passed=False,
            details="Status: 200",
            remediation="Require authentication",
        )
        with patch.object(full_app_module.MCPScanner, "scan", return_value=[check]):
            response = self.client.post(
                "/api/scans/mcp",
                json={"target_url": "https://active.example.test", "authorized": True},
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 200)
        scan = response.get_json()["scan"]
        self.assertTrue(scan["has_critical"])
        self.assertEqual(scan["critical_count"], 1)
        history = self.client.get("/api/scans/mcp", headers=self.headers).get_json()["scans"]
        self.assertEqual(history[0]["id"], scan["id"])
        self.assertEqual(history[0]["status"], "completed")
        findings = self.client.get("/api/findings", headers=self.headers).get_json()["findings"]
        self.assertEqual(findings[0]["server"], "https://active.example.test")
        self.assertEqual(findings[0]["remediation"], "Require authentication")


if __name__ == "__main__":
    unittest.main()
