import importlib.util
import os
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch


class AccountBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            'DB_FILE': os.path.join(self.temp.name, 'test.db'),
            'JWT_SECRET': 'test-only-key-that-is-at-least-32-bytes-long',
            'VATA_AUTH_BRIDGE_ENABLED': '1',
        })
        self.env.start()
        spec = importlib.util.spec_from_file_location('bridge_app_fixture', 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.client = self.module.app.test_client()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def token(self, identity='-1', owner='fixture_owner', bridge=True):
        from flask_jwt_extended import create_access_token
        with self.module.app.app_context():
            token = create_access_token(identity=identity, additional_claims={
                'owner_user_id': owner, 'bridge': bridge,
            })
        return {'Authorization': f'Bearer {token}'}

    def test_legacy_name_login_disabled(self):
        self.assertEqual(self.client.post('/auth/register', json={'org_name': 'Legacy'}).status_code, 410)

    def test_untrusted_tokens_rejected(self):
        self.assertEqual(self.client.get('/api/findings').status_code, 401)
        self.assertEqual(self.client.get('/api/findings', headers=self.token(bridge=False)).status_code, 403)

    def test_missing_storage_fails_readiness_without_creating_an_empty_database(self):
        os.remove(self.module.DB_FILE)
        self.assertEqual(self.client.get('/health').status_code, 503)
        self.assertEqual(self.client.get('/api/findings', headers=self.token()).status_code, 503)
        self.assertFalse(os.path.exists(self.module.DB_FILE))

    def test_missing_schema_blocks_requests_and_restoration_recovers_readiness(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute('ALTER TABLE organizations RENAME TO saved_organizations')
        self.assertEqual(self.client.get('/health').status_code, 503)
        self.assertEqual(self.client.post('/internal/provision', headers=self.token()).status_code, 503)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute('ALTER TABLE saved_organizations RENAME TO organizations')
        self.assertEqual(self.client.get('/health').status_code, 200)

    def test_workspace_cannot_be_claimed_by_other_owner(self):
        self.assertEqual(self.client.post('/internal/provision', headers=self.token()).status_code, 200)
        self.assertEqual(self.client.post('/internal/provision', headers=self.token(owner='other')).status_code, 409)
        self.assertEqual(self.client.post('/internal/provision', headers=self.token(identity='1')).status_code, 400)

    def test_parallel_workspace_provision_is_idempotent(self):
        headers = self.token()
        start = threading.Barrier(12)
        def provision(_):
            with self.module.app.test_client() as client:
                start.wait(timeout=10)
                return client.post('/internal/provision', headers=headers).status_code
        with ThreadPoolExecutor(max_workers=12) as executor:
            statuses = list(executor.map(provision, range(12)))
        self.assertEqual(statuses, [200] * 12)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM organizations WHERE id=-1').fetchone()[0], 1)

    def test_parallel_owners_cannot_claim_each_others_workspace(self):
        tokens = {owner: self.token(owner=owner) for owner in ('first_owner', 'second_owner')}
        owners = ['first_owner', 'second_owner'] * 6
        start = threading.Barrier(12)
        def provision(owner):
            with self.module.app.test_client() as client:
                start.wait(timeout=10)
                return owner, client.post('/internal/provision', headers=tokens[owner]).status_code
        with ThreadPoolExecutor(max_workers=12) as executor:
            results = list(executor.map(provision, owners))
        with sqlite3.connect(self.module.DB_FILE) as conn:
            winner = conn.execute('SELECT owner_user_id FROM organizations WHERE id=-1').fetchone()[0]
        for owner, status in results:
            self.assertEqual(status, 200 if owner == winner else 409)

    def test_findings_are_isolated_between_accounts(self):
        for identity in ('-1', '-2'):
            self.assertEqual(self.client.post('/internal/provision', headers=self.token(identity=identity)).status_code, 200)
        headers = self.token()
        created = self.client.post('/api/findings', headers=headers, json={
            'vector_type': 'Fixture', 'severity': 'critical',
            'description': 'Owned test finding', 'remediation': 'Test only',
        })
        self.assertEqual(created.status_code, 201)
        first = self.client.get('/api/findings', headers=headers).get_json()
        second = self.client.get('/api/findings', headers=self.token(identity='-2')).get_json()
        self.assertEqual(len(first['findings']), 1)
        self.assertEqual(second['findings'], [])


if __name__ == '__main__':
    unittest.main()
