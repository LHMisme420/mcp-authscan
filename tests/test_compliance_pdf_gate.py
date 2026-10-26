"""Gate tests: compliance PDF assessment state when scans are missing, failed, or completed."""
import base64
import importlib.util
import os
import re
import sqlite3
import tempfile
import unittest
import zlib
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from flask_jwt_extended import create_access_token

from mcp_authscan.compliance_pdf import _plain_text


def pdf_content_streams(data):
    """Decode ReportLab's ASCII85/Flate-compressed page content for assertions."""
    output = []
    for stream in re.findall(rb'stream\r?\n(.*?)\r?\n?endstream', data, flags=re.DOTALL):
        if stream.endswith(b'~>'):
            stream = base64.a85decode(stream, adobe=True)
        try:
            output.append(zlib.decompress(stream))
        except zlib.error:
            continue
    return b'\n'.join(output)


class CompliancePdfGateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.environment = patch.dict(os.environ, {
            'DB_FILE': str(Path(self.temp.name) / 'reports.sqlite'),
            'JWT_SECRET': 'gate-test-fixture-key-at-least-32-bytes',
            'VATA_AUTH_BRIDGE_ENABLED': '0',
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        spec = importlib.util.spec_from_file_location('compliance_pdf_fixture', 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.client = self.module.app.test_client()
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute('INSERT INTO organizations(id,name) VALUES(?,?)', (1, 'Test Workspace'))
            # Org 1 has three findings but no completed scans
            conn.executemany(
                '''INSERT INTO findings(org_id,server_name,rule,vector_type,severity,description,remediation)
                   VALUES(?,?,?,?,?,?,?)''',
                [
                    (1, 'mcp.example.test', 'Input safety', 'scanner', 'critical', 'Critical finding', 'Fix it'),
                    (1, 'mcp.example.test', 'Cred handling', 'scanner', 'HIGH', 'High finding', 'Fix it'),
                    (1, 'mcp.example.test', 'Other', 'scanner', 'LOW', 'Low finding', 'Fix it'),
                ],
            )

    def headers(self, identity='1'):
        with self.module.app.app_context():
            token = create_access_token(identity=str(identity))
        return {'Authorization': f'Bearer {token}'}

    def test_no_score_without_a_completed_scan(self):
        """Workspace with findings but zero completed scans shows 'Not assessed', no percentage."""
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        page_text = pdf_content_streams(response.data)
        # Must NOT contain any percentage sign
        self.assertNotIn(b'%', page_text)
        # Must contain "Not assessed: no scans recorded" or similar
        self.assertIn(b'not assessed', page_text.lower())
        self.assertIn(b'no scans', page_text.lower())
        summary = self.client.get('/api/reports/compliance', headers=self.headers())
        self.assertEqual(summary.status_code, 200)
        self.assertIsNone(summary.json['compliance_score'])

    def test_failed_and_running_scans_are_named_but_not_scored(self):
        """Workspace with only failed/running scans shows 'Not assessed', names the scans."""
        now = datetime.now(timezone.utc)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.executemany(
                '''INSERT INTO scan_runs(org_id,target,status,total_checks,findings_count,started_at)
                   VALUES(?,?,?,?,?,?)''',
                [
                    (1, 'https://mcp.failed.test', 'failed', 5, 0, now),
                    (1, 'https://mcp.running.test', 'running', 0, 0, now),
                ],
            )
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        page_text = pdf_content_streams(response.data)
        # Must NOT contain a percentage
        self.assertNotIn(b'%', page_text)
        # Must contain both target names and their statuses
        self.assertIn(b'mcp.failed.test', page_text.lower())
        self.assertIn(b'mcp.running.test', page_text.lower())
        self.assertIn(b'failed', page_text.lower())
        self.assertIn(b'running', page_text.lower())
        # Still no numeric assessment
        self.assertIn(b'not assessed', page_text.lower())
        summary = self.client.get('/api/reports/compliance', headers=self.headers())
        self.assertEqual(summary.status_code, 200)
        self.assertIsNone(summary.json['compliance_score'])

    def test_completed_scan_shows_score_and_per_scan_block(self):
        """Workspace with a completed scan shows percentage and per-scan block."""
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute(
                'INSERT INTO scan_runs(org_id,target,status,total_checks,findings_count,started_at,completed_at) '
                'VALUES(?,?,?,?,?,?,?)',
                (1, 'mcp.completed.unique.test', 'completed', 9, 1,
                 '2026-10-25 12:00:00', '2026-10-25 12:00:00'))
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        page_text = pdf_content_streams(response.data)
        # Must contain percentage (score is computed)
        self.assertIn(b'%', page_text)
        # Per-scan block shows unique target (only place it appears)
        self.assertIn(b'mcp.completed.unique.test', page_text)
        # Per-scan block shows exact completion timestamp
        self.assertIn(b'2026-10-25 12:00:00', page_text)
        # Per-scan block shows scan status
        self.assertIn(b'completed', page_text.lower())
        # Must NOT say "Not assessed"
        self.assertNotIn(b'not assessed', page_text.lower())
        summary = self.client.get('/api/reports/compliance', headers=self.headers())
        self.assertEqual(summary.status_code, 200)
        self.assertIsNotNone(summary.json['compliance_score'])
