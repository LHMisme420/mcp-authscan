"""The PDF report uses the authenticated workspace and its existing score."""
import importlib.util
import base64
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import unittest
import zlib
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


class CompliancePdfTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.environment = patch.dict(os.environ, {
            'DB_FILE': str(Path(self.temp.name) / 'reports.sqlite'),
            'JWT_SECRET': 'report-test-fixture-key-at-least-32-bytes',
            'VATA_AUTH_BRIDGE_ENABLED': '0',
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        spec = importlib.util.spec_from_file_location('compliance_pdf_fixture', 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.client = self.module.app.test_client()
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.executemany(
                'INSERT INTO organizations(id,name) VALUES(?,?)',
                [(1, 'Workspace <Alpha> & Co'), (2, 'Separate workspace')],
            )
            conn.executemany(
                '''INSERT INTO findings(org_id,server_name,rule,vector_type,severity,description,remediation)
                   VALUES(?,?,?,?,?,?,?)''',
                [
                    (1, 'mcp.example.test', 'Input safety', 'scanner', 'critical',
                     '<script>alert("not markup")</script>', 'Escape untrusted text'),
                    (1, 'mcp.example.test', 'Credential handling', 'scanner', 'HIGH',
                     'High test finding', ''),
                    (1, 'mcp.example.test', 'Unknown classification', 'scanner', None,
                     'Unclassified test finding', ''),
                    (2, 'private.example.test', 'Private other-org rule', 'scanner', 'critical',
                     'OtherWorkspaceSecretMarker', 'Other workspace remediation'),
                ],
            )

    def headers(self, identity='1'):
        with self.module.app.app_context():
            token = create_access_token(identity=str(identity))
        return {'Authorization': f'Bearer {token}'}

    def test_pdf_is_valid_download_with_existing_score_and_severity_counts(self):
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, 'application/pdf')
        self.assertIn('attachment', response.headers['Content-Disposition'])
        self.assertIn('vata-compliance-summary.pdf', response.headers['Content-Disposition'])
        self.assertTrue(response.data.startswith(b'%PDF-'))
        self.assertTrue(response.data.rstrip().endswith(b'%%EOF'))
        page_text = pdf_content_streams(response.data)
        # The existing score is 100 - (100 critical + 50 high) / 3 findings.
        self.assertIn(b'50%', page_text)
        self.assertIn(b'critical', page_text.lower())
        self.assertIn(b'other', page_text.lower())

    def test_pdf_isolated_to_authenticated_workspace_and_escapes_untrusted_markup(self):
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        page_text = pdf_content_streams(response.data)
        self.assertNotIn(b'OtherWorkspaceSecretMarker', page_text)
        self.assertNotIn(b'Other workspace remediation', page_text)
        self.assertNotIn(b'Private other-org rule', page_text)
        self.assertIn('&lt;script&gt;', _plain_text('<script>alert("not markup")</script>'))

    def test_pdf_requires_a_valid_identity_and_existing_workspace(self):
        self.assertEqual(self.client.get('/api/reports/pdf').status_code, 401)
        self.assertEqual(
            self.client.get('/api/reports/pdf', headers=self.headers('999')).status_code,
            404,
        )

    def test_pdf_preserves_finding_counts_when_severity_is_missing(self):
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            summary = self.module.organization_summary(conn, 1)
        self.assertEqual(summary['total_findings'], 3)
        self.assertEqual(summary['critical_findings'], 1)
        self.assertEqual(summary['high_findings'], 1)

    def test_missing_database_fails_closed_without_creating_a_replacement(self):
        os.remove(self.module.DB_FILE)
        response = self.client.get('/api/reports/pdf', headers=self.headers())
        self.assertEqual(response.status_code, 503)
        self.assertFalse(Path(self.module.DB_FILE).exists())


if __name__ == '__main__':
    unittest.main()
