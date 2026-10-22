"""Regression checks for the removal of subscription restrictions."""
import importlib.util
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from flask_jwt_extended import create_access_token


class WorkspaceAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            'DB_FILE': os.path.join(self.temp.name, 'workspace.db'),
            'JWT_SECRET': 'test-fixture-only-secret-at-least-32-bytes',
            'VATA_AUTH_BRIDGE_ENABLED': '0',
        })
        self.env.start()
        spec = importlib.util.spec_from_file_location('workspace_fixture_app', 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.client = self.module.app.test_client()
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("INSERT INTO organizations(id,name,api_key) VALUES(1,'Fixture','fixture-key')")
            conn.execute("INSERT INTO organizations(id,name,api_key) VALUES(2,'Other','other-fixture-key')")
        with self.module.app.app_context():
            self.headers = {'Authorization': 'Bearer ' + create_access_token(identity='1')}
        self.scanner = patch.object(self.module.MCPScanner, 'scan', return_value=[])
        self.scanner.start()

    def tearDown(self):
        self.scanner.stop()
        self.env.stop()
        self.temp.cleanup()

    def scan(self):
        return self.client.post('/api/scans/mcp', headers=self.headers,
                                json={'target_url': 'https://fixture.example.test', 'authorized': True})

    def test_more_than_five_scans_without_a_subscription(self):
        for _ in range(8):
            self.assertEqual(self.scan().status_code, 200)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM scan_runs WHERE org_id=1').fetchone()[0], 8)

    def test_calendar_month_accounting_still_resets(self):
        with patch('mcp_authscan.tiers.utc_now', return_value=datetime(2026, 12, 31, tzinfo=timezone.utc)):
            for _ in range(6):
                self.assertEqual(self.scan().status_code, 200)
        with patch('mcp_authscan.tiers.utc_now', return_value=datetime(2027, 1, 1, tzinfo=timezone.utc)):
            self.assertEqual(self.scan().status_code, 200)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            self.assertEqual(conn.execute('SELECT monthly_scan_count FROM organizations WHERE id=1').fetchone()[0], 1)

    def test_expired_legacy_subscription_cannot_block_access(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("UPDATE organizations SET subscription_tier='pro',subscription_expires_at='2000-01-01T00:00:00Z' WHERE id=1")
        for _ in range(7):
            self.assertEqual(self.scan().status_code, 200)

    def test_old_history_visible_and_tenants_still_isolated(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("INSERT INTO findings(org_id,severity,description,created_at) VALUES(1,'critical','Old',datetime('now','-60 days'))")
            conn.execute("INSERT INTO findings(org_id,severity,description) VALUES(2,'low','Other organization')")
            conn.execute("INSERT INTO scan_runs(org_id,target,status,started_at) VALUES(1,'https://fixture.example.test','completed',datetime('now','-60 days'))")
        findings = self.client.get('/api/findings', headers=self.headers).json['findings']
        self.assertEqual([f['description'] for f in findings], ['Old'])
        self.assertEqual(self.client.get('/api/threat-intelligence', headers=self.headers).json['critical'], 1)
        self.assertEqual(len(self.client.get('/api/scans/mcp', headers=self.headers).json['scans']), 1)

    def test_finding_creation_allowed_but_auth_and_validation_remain(self):
        self.assertEqual(self.client.post('/api/findings', headers=self.headers, json={'description': 'Manual finding'}).status_code, 201)
        self.assertEqual(self.client.post('/api/scans/mcp', headers=self.headers, json={'target_url': 'bad-url'}).status_code, 400)
        self.assertEqual(self.client.get('/api/findings').status_code, 401)


if __name__ == '__main__':
    unittest.main()
