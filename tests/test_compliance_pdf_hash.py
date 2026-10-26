"""Versioned report hash regression and authenticated JSON/PDF parity tests."""
import copy
import hashlib
import json
import sqlite3
import unittest

from mcp_authscan.compliance_pdf import (
    canonical_report_content,
    compute_canonical_findings_hash,
)
from tests import test_compliance_pdf_gate as gate


class CanonicalReportHashTests(unittest.TestCase):
    def setUp(self):
        self.findings = [{
            'server_name': 'mcp.example.test', 'rule': 'Unicode café',
            'vector_type': 'scanner', 'severity': 'HIGH',
            'description': 'Check input', 'remediation': None,
            'created_at': '2026-10-26 12:00:00',
        }]
        self.counts = {'HIGH': 1, 'LOW': 0}
        self.scans = [{
            'target': 'https://mcp.example.test', 'status': 'completed',
            'total_checks': 10, 'findings_count': 1,
            'started_at': '2026-10-26 12:00:00',
            'completed_at': '2026-10-26 12:01:00', 'attested_at': None,
        }]

    def test_exact_serialization_and_scope(self):
        payload = canonical_report_content(self.findings, self.counts, self.scans)
        self.assertEqual(payload['schema_version'], 2)
        self.assertEqual(payload['scan_runs'], self.scans)
        expected = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
            allow_nan=False,
        ).encode('utf-8')).hexdigest()
        self.assertEqual(expected, compute_canonical_findings_hash(
            self.findings, self.counts, self.scans))
        # Input dictionary insertion order is not part of the contract.
        self.assertEqual(expected, compute_canonical_findings_hash(
            self.findings, dict(reversed(list(self.counts.items()))), self.scans))

    def test_every_scan_field_affects_hash(self):
        baseline = compute_canonical_findings_hash(self.findings, self.counts, self.scans)
        for field in self.scans[0]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.scans)
                changed[0][field] = 99 if field in ('total_checks', 'findings_count') else 'changed'
                self.assertNotEqual(baseline, compute_canonical_findings_hash(
                    self.findings, self.counts, changed))

    def test_findings_and_counts_affect_hash(self):
        baseline = compute_canonical_findings_hash(self.findings, self.counts, self.scans)
        for field in self.findings[0]:
            with self.subTest(field=field):
                changed = copy.deepcopy(self.findings)
                changed[0][field] = 'changed'
                self.assertNotEqual(baseline, compute_canonical_findings_hash(
                    changed, self.counts, self.scans))
        self.assertNotEqual(baseline, compute_canonical_findings_hash(
            self.findings, {'HIGH': 2}, self.scans))

    def test_array_order_is_preserved(self):
        second = dict(self.scans[0], target='second.test')
        self.assertNotEqual(
            compute_canonical_findings_hash(self.findings, self.counts, self.scans + [second]),
            compute_canonical_findings_hash(self.findings, self.counts, [second] + self.scans))


class ReportExportHashTests(unittest.TestCase):
    # Reuse the isolated database setup without inheriting its test methods.
    setUp = gate.CompliancePdfGateTests.setUp
    headers = gate.CompliancePdfGateTests.headers

    def test_json_recompute_matches_two_pdf_exports(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute(
                '''INSERT INTO scan_runs(org_id,target,status,total_checks,findings_count)
                   VALUES(?,?,?,?,?)''',
                (1, 'https://hash.example.test', 'completed', 12, 3))
            conn.execute('INSERT INTO organizations(id,name) VALUES(?,?)', (2, 'Other'))
            conn.execute(
                '''INSERT INTO scan_runs(org_id,target,status,total_checks,findings_count)
                   VALUES(?,?,?,?,?)''',
                (2, 'https://private-other.test', 'completed', 999, 999))
        response = self.client.get('/api/reports/pdf?format=json', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        data = response.json
        payload = data['canonical_report']
        self.assertEqual(len(payload['scan_runs']), 1)
        self.assertEqual(len(payload['findings']), 3)
        self.assertNotIn('private-other.test', response.get_data(as_text=True))
        expected = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
            allow_nan=False,
        ).encode('utf-8')).hexdigest()
        self.assertEqual(expected, data['content_hash'])
        for _ in range(2):
            pdf = self.client.get('/api/reports/pdf', headers=self.headers())
            self.assertEqual(pdf.status_code, 200)
            text = gate.pdf_content_streams(pdf.data)
            self.assertIn(expected.encode(), text)
            self.assertIn(b'canonical_report', text)
            self.assertIn(b'ensure_ascii=True', text)
            self.assertIn(b'allow_nan=False', text)
            self.assertIn(b'total_checks', text)
            self.assertIn(b'findings_count', text)

    def test_json_requires_auth_and_workspace(self):
        self.assertEqual(self.client.get('/api/reports/pdf?format=json').status_code, 401)
        response = self.client.get(
            '/api/reports/pdf?format=json', headers=self.headers('999'))
        self.assertEqual(response.status_code, 404)

    def test_export_cap_retains_full_severity_counts(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.executemany(
                'INSERT INTO findings(org_id,severity,description) VALUES(?,?,?)',
                [(1, 'LOW', f'Finding {index}') for index in range(1000)])
        response = self.client.get('/api/reports/pdf?format=json', headers=self.headers())
        self.assertEqual(response.status_code, 200)
        payload = response.json['canonical_report']
        self.assertEqual(len(payload['findings']), 1000)
        self.assertEqual(sum(payload['severity_counts'].values()), 1003)
        self.assertEqual(payload['scan_runs'], [])

    def test_changed_scan_context_changes_export_hash(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute(
                '''INSERT INTO scan_runs(org_id,target,status,total_checks,findings_count)
                   VALUES(?,?,?,?,?)''',
                (1, 'before.test', 'completed', 10, 3))
        original = self.client.get(
            '/api/reports/pdf?format=json', headers=self.headers()).json['content_hash']
        for field, value in [('target', 'after.test'), ('total_checks', 11), ('findings_count', 4)]:
            with self.subTest(field=field):
                with sqlite3.connect(self.module.DB_FILE) as conn:
                    conn.execute(f'UPDATE scan_runs SET {field}=? WHERE org_id=1', (value,))
                updated = self.client.get(
                    '/api/reports/pdf?format=json', headers=self.headers()).json['content_hash']
                self.assertNotEqual(original, updated)
                original = updated

    def test_invalid_format_is_explicit(self):
        response = self.client.get('/api/reports/pdf?format=xml', headers=self.headers())
        self.assertEqual(response.status_code, 400)


if __name__ == '__main__':
    unittest.main()
