"""Regression checks for dashboard data, using isolated temporary databases."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from flask_jwt_extended import create_access_token


class FindingsRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db_path = str(Path(self.temp.name) / "findings.db")
        spec = importlib.util.spec_from_file_location(
            "isolated_dashboard", Path(__file__).resolve().parents[1] / "app.py"
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {
            "DB_FILE": self.db_path,
            "JWT_SECRET": "local-test-secret-key-0123456789abcdef",
        }):
            spec.loader.exec_module(module)
        self.client = module.app.test_client()
        self.module = module
        self.org_id = 1
        with sqlite3.connect(self.db_path) as connection:
            connection.execute("INSERT INTO organizations (id,name) VALUES (1,'test-org'),(2,'other-org')")
        self.headers = self.headers_for(self.org_id)

    def headers_for(self, org_id):
        with self.module.app.app_context():
            token = create_access_token(identity=str(org_id))
        return {"Authorization": f"Bearer {token}"}

    def insert(self, severity, created_at="2026-10-14 12:00:00", org_id=None):
        with sqlite3.connect(self.db_path) as connection:
            cursor = connection.execute(
                "INSERT INTO findings (org_id, vector_type, severity, description, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (org_id or self.org_id, "test-rule", severity, "test finding", created_at),
            )
            return cursor.lastrowid

    def test_new_scan_results_appear_before_older_findings(self):
        for _ in range(25):
            self.insert("HIGH")
        newest = self.insert("LOW", "2026-10-14 13:00:00")
        tied_newest = self.insert("MEDIUM", "2026-10-14 13:00:00")
        response = self.client.get("/api/findings", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        ids = [finding["id"] for finding in response.json["findings"][:20]]
        self.assertEqual(ids[:2], [tied_newest, newest])

    def test_totals_include_all_rows_and_case_variants(self):
        for _ in range(102):
            self.insert(" high ")
        for severity in ("critical", "MEDIUM", "Low"):
            self.insert(severity)
        response = self.client.get("/api/threat-intelligence", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        for key, value in {
            "critical": 1, "high": 102, "medium": 1, "low": 1, "total_findings": 105
        }.items():
            self.assertEqual(response.json[key], value)
        compliance = self.client.get("/api/reports/compliance", headers=self.headers)
        self.assertEqual(compliance.json["critical_findings"], 1)
        self.assertEqual(compliance.json["high_findings"], 102)

    def test_other_organization_findings_are_not_returned_or_counted(self):
        self.insert("CRITICAL", org_id=2)
        self.insert("LOW")
        findings = self.client.get("/api/findings", headers=self.headers)
        self.assertEqual(len(findings.json["findings"]), 1)
        stats = self.client.get("/api/threat-intelligence", headers=self.headers)
        self.assertEqual(stats.json["critical"], 0)
        self.assertEqual(stats.json["low"], 1)
        self.assertEqual(stats.json["total_findings"], 1)

    def test_empty_organization_has_zero_counts(self):
        response = self.client.get("/api/threat-intelligence", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        for key in ("critical", "high", "medium", "low", "total_findings"):
            self.assertEqual(response.json[key], 0)

    def test_org_10_test_finding_reaches_dashboard_endpoints(self):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                "INSERT INTO organizations (id, name) VALUES (10, 'isolated-org-10')"
            )
            connection.execute(
                "INSERT INTO findings (org_id, server_name, rule, vector_type, severity, description) "
                "VALUES (10, 'test.com', 'Test Rule', 'Test Rule', 'critical', 'Test finding')"
            )
        self.assertEqual(self.client.post("/auth/login", json={"org_name": "isolated-org-10"}).status_code, 410)
        headers = self.headers_for(10)
        findings = self.client.get("/api/findings", headers=headers)
        stats = self.client.get("/api/threat-intelligence", headers=headers)
        self.assertEqual(findings.status_code, 200)
        self.assertEqual(findings.json["findings"][0]["server"], "test.com")
        self.assertEqual(findings.json["findings"][0]["description"], "Test finding")
        self.assertEqual(stats.json["critical"], 1)
        self.assertEqual(stats.json["total_findings"], 1)


if __name__ == "__main__":
    unittest.main()
