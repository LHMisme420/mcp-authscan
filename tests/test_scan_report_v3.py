"""Isolated schema-3 web/CLI parity tests; never use workspace or production data."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from mcp_authscan import report_verify as rv
from mcp_authscan.scan_report import envelope, save_snapshot, checks_payload
from mcp_authscan.findings_schema import initialize_database
from mcp_authscan.scanner import Check, RiskLevel


def example():
    findings = [{
        "server_name": "SYNTHETIC — not a client", "rule": "SYNTHETIC-CACHE",
        "vector_type": "OAuth", "severity": "MEDIUM",
        "severity_basis": "Synthetic missing cache directive only",
        "endpoint": "/oauth/token", "description": "Synthetic café response",
        "remediation": "Set Cache-Control: no-store",
    }]
    return {
        "target": "https://mcp.example.invalid", "status": "completed",
        "total_checks": 4, "findings_count": 1,
        # The probe-set form app.py stamps on web reports (a web check engine source digest).
        "probe_set_version": "web-source-sha256:" + "a" * 64, "coverage": {
            "PASS": 1, "FAIL": 1, "NOT_OBSERVED": 1, "EXCLUDED": 1,
        },
        "severity_counts": rv.severity_counts(findings), "findings": findings,
    }


class HashTests(unittest.TestCase):
    def test_exact_keys_serialization_and_all_exclusions(self):
        original = example()
        altered = copy.deepcopy(original)
        for key in ("started_at", "completed_at", "created_at", "attested_at",
                    "session_id", "headers", "server"):
            altered[key] = {"Date": "different"}
            altered["findings"][0][key] = "different"
        canonical = rv.canonical_report(original, original["findings"])
        self.assertEqual(set(canonical), set(rv.HASHED_KEYS) | {"findings"})
        self.assertEqual(set(canonical["findings"][0]), set(rv.FINDING_KEYS))
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True, allow_nan=False).encode("utf-8")
        self.assertIn(b"caf\\u00e9", serialized)
        self.assertEqual(rv.compute(original, original["findings"])[0],
                         hashlib.sha256(serialized).hexdigest())
        self.assertEqual(rv.compute(original, original["findings"]),
                         rv.compute(altered, altered["findings"]))

    def test_every_requested_field_is_bound(self):
        original = example()
        digest = rv.compute(original, original["findings"])[0]
        for key in rv.HASHED_KEYS:
            changed = copy.deepcopy(original)
            if key in ("findings_count", "severity_counts"):
                changed[key] = 999
                with self.assertRaises((ValueError, TypeError)):
                    rv.compute(changed, changed["findings"])
                continue
            changed[key] = "changed"
            self.assertNotEqual(digest, rv.compute(changed, changed["findings"])[0], key)
        for key in rv.FINDING_KEYS:
            changed = copy.deepcopy(original)
            changed["findings"][0][key] = "changed"
            if key == "severity":
                changed["severity_counts"] = rv.severity_counts(changed["findings"])
            self.assertNotEqual(digest, rv.compute(changed, changed["findings"])[0], key)

    def test_no_truncation_nan_or_array_order_dependency(self):
        report = example()
        report["findings"] *= 1001
        report["findings_count"] = 1001
        report["severity_counts"] = rv.severity_counts(report["findings"])
        self.assertEqual(len(envelope(report)["findings"]), 1001)
        truncated = copy.deepcopy(report)
        truncated["findings"] = truncated["findings"][:1000]
        with self.assertRaises(ValueError):
            envelope(truncated)
        report["findings"][-1] = dict(report["findings"][-1], description="another")
        digest = rv.compute(report, report["findings"])[0]
        report["findings"].reverse()
        self.assertEqual(digest, rv.compute(report, report["findings"])[0])
        report["coverage"] = float("nan")
        with self.assertRaises(ValueError):
            envelope(report)

    def test_web_engine_does_not_invent_coverage(self):
        check = Check("rule", "description", "/mcp", "POST", RiskLevel.MEDIUM,
                      False, "Date: variable response details", "remediation", "basis")
        report = checks_payload("https://mcp.example.invalid", [check], "actual-code-id")
        self.assertIsNone(report["coverage"])
        self.assertEqual(report["findings"][0]["description"], "description")
        self.assertNotIn("Date", json.dumps(envelope(report)["canonical_report"]))


class WebExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        db = str(Path(cls.directory.name) / "isolated.sqlite")
        cls.previous = {key: os.environ.get(key) for key in ("DB_FILE", "JWT_SECRET")}
        os.environ.update(DB_FILE=db, JWT_SECRET="synthetic-test-secret-only-at-least-32-chars")
        spec = importlib.util.spec_from_file_location("isolated_v3_app", Path(__file__).parents[1] / "app.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.module.app.config["TESTING"] = True
        with sqlite3.connect(db) as conn:
            conn.execute("INSERT INTO organizations(id,name) VALUES(991,'SYNTHETIC TEST ONLY')")
        cls.client = cls.module.app.test_client()
        from flask_jwt_extended import create_access_token
        with cls.module.app.app_context():
            cls.token = create_access_token(identity="991")
        cls.headers = {"Authorization": "Bearer " + cls.token}

    @classmethod
    def tearDownClass(cls):
        for key, value in cls.previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        cls.directory.cleanup()

    def seed(self, payload=None, org=991):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            cursor = conn.execute("INSERT INTO scan_runs(org_id,target,status) VALUES (?,?,?)",
                                  (org, "https://mcp.example.invalid", "completed"))
            scan_id = cursor.lastrowid
            if payload is not None:
                save_snapshot(conn, org, scan_id, payload)
        return scan_id

    def test_real_web_json_export_matches_cli_verifier(self):
        report = envelope(example())
        scan_id = self.seed(report)
        response = self.client.get(
            f"/api/reports/pdf?scan_id={scan_id}&format=json", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        web = response.get_json()
        self.assertEqual(web["report_hash"], report["report_hash"])
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "cli.json"
            filename.write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(rv.verify(filename), ("MATCH", web["report_hash"]))
        self.assertNotIn("started_at", web["canonical_report"])

    def test_auth_tenant_legacy_and_input_guards(self):
        own = self.seed()
        other = self.seed(example(), org=992)
        url = "/api/reports/pdf?format=json&scan_id="
        self.assertEqual(self.client.get(url + str(own)).status_code, 401)
        self.assertEqual(self.client.get(url + str(other), headers=self.headers).status_code, 404)
        response = self.client.get(url + str(own), headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "REPORT_NOT_REPRODUCIBLE")
        self.assertEqual(self.client.get(url + "x", headers=self.headers).status_code, 400)

    def test_pdf_has_schema_three_and_excludes_timestamp_instructions(self):
        from unittest.mock import patch
        from mcp_authscan import scan_report
        scan_id = self.seed(example())
        paragraphs = []
        original = scan_report.Paragraph
        def capture(text, *args, **kwargs):
            paragraphs.append(text)
            return original(text, *args, **kwargs)
        with patch.object(scan_report, "Paragraph", capture):
            response = self.client.get(f"/api/reports/pdf?scan_id={scan_id}", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data.startswith(b"%PDF-"))
        text = "\n".join(paragraphs)
        self.assertIn("schema version 3", text)
        self.assertIn("No timestamps are included in the hash", text)
        self.assertIn(envelope(example())["report_hash"], text)
        self.assertNotIn("including scan_runs", text)

    def test_snapshot_tampering_fails_closed(self):
        scan_id = self.seed(example())
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("UPDATE scan_report_snapshots SET report_hash='wrong' WHERE scan_id=?", (scan_id,))
        response = self.client.get(f"/api/reports/pdf?scan_id={scan_id}&format=json", headers=self.headers)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["code"], "REPORT_INTEGRITY_FAILED")

    def test_web_scan_saves_complete_snapshot_with_real_endpoint_and_basis(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        check = Check("synthetic rule", "stable description", "/mcp", "POST",
                      RiskLevel.MEDIUM, False, "variable raw evidence", "remediation",
                      "synthetic observed basis")
        scanner = SimpleNamespace(target_url="https://mcp.example.invalid",
                                  scan=lambda: [check])
        with patch.object(self.module, "MCPScanner", return_value=scanner):
            response = self.client.post("/api/scans/mcp",
                                        json={"target_url": scanner.target_url, "authorized": True},
                                        headers=self.headers)
        self.assertEqual(response.status_code, 200, response.get_json())
        with sqlite3.connect(self.module.DB_FILE) as conn:
            scan_id = conn.execute("SELECT max(id) FROM scan_runs WHERE org_id=991").fetchone()[0]
        report = self.client.get(f"/api/reports/pdf?scan_id={scan_id}&format=json",
                                 headers=self.headers).get_json()
        self.assertEqual(report["findings"][0]["endpoint"], "/mcp")
        self.assertEqual(report["findings"][0]["severity_basis"], "synthetic observed basis")
        self.assertIsNone(report["coverage"])
        self.assertTrue(report["probe_set_version"].startswith("web-source-sha256:"))
        self.assertEqual(report["findings_count"], 1)


if __name__ == "__main__":
    unittest.main()
