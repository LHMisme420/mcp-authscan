"""Tier authorization checks use isolated databases and verified JWT identities."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from flask_jwt_extended import create_access_token


class TierAccessTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.env = patch.dict(os.environ, {
            'DB_FILE': str(Path(temp.name) / 'tiers.sqlite'),
            'JWT_SECRET': 'tier-test-fixture-key-at-least-32-bytes',
            'VATA_AUTH_BRIDGE_ENABLED': '0',
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        spec = importlib.util.spec_from_file_location('tier_access_fixture', 'app.py')
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.client = self.module.app.test_client()
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.executemany(
                'INSERT INTO organizations(id,name,subscription_tier) VALUES(?,?,?)',
                [(1, 'Free fixture', 'free'), (2, 'Pro fixture', 'pro'),
                 (3, 'Enterprise fixture', 'enterprise'), (4, 'Unknown fixture', 'unknown')],
            )

    def headers(self, identity='1', **claims):
        with self.module.app.app_context():
            token = create_access_token(identity=identity, additional_claims=claims)
        return {'Authorization': f'Bearer {token}'}

    def request(self, method, path, headers=None):
        return self.client.open(
            path, method=method, headers=headers,
            json={'severity': 'medium', 'description': 'Tier test finding'} if method == 'POST' else None,
        )

    def test_all_supported_tiers_can_use_existing_endpoints(self):
        for identity in ('1', '2', '3'):
            for method, path, expected in (
                ('GET', '/api/findings', 200),
                ('POST', '/api/findings', 201),
                ('GET', '/api/threat-intelligence', 200),
            ):
                with self.subTest(identity=identity, method=method, path=path):
                    self.assertEqual(self.request(method, path, self.headers(identity)).status_code, expected)

    def test_missing_and_invalid_tokens_are_rejected(self):
        for method, path in (
            ('GET', '/api/findings'), ('POST', '/api/findings'),
            ('GET', '/api/threat-intelligence'),
        ):
            with self.subTest(method=method, path=path):
                self.assertEqual(self.request(method, path).status_code, 401)
                token = self.headers()['Authorization']
                # Change the signature while retaining a well-formed JWT.
                signature = token.rsplit('.', 1)[1]
                invalid = token.rsplit('.', 1)[0] + '.' + ('A' if signature[0] != 'A' else 'B') + signature[1:]
                response = self.request(method, path, {'Authorization': invalid})
                self.assertEqual(response.status_code, 422)

    def test_unknown_tier_and_missing_organization_are_forbidden(self):
        for identity in ('4', '999'):
            for method, path in (
                ('GET', '/api/findings'), ('POST', '/api/findings'),
                ('GET', '/api/threat-intelligence'),
            ):
                with self.subTest(identity=identity, method=method, path=path):
                    self.assertEqual(self.request(method, path, self.headers(identity)).status_code, 403)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM findings').fetchone()[0], 0)

    def premium_response(self, headers):
        @self.module.require_tier('pro', 'enterprise')
        def premium_view():
            return self.module.jsonify(status='ok')

        with self.module.app.test_request_context(headers=headers):
            return self.module.app.make_response(premium_view())

    def test_paid_only_decorator_denies_free_and_allows_pro_and_enterprise(self):
        for identity, expected in (('1', 403), ('2', 200), ('3', 200), ('4', 403), ('999', 403)):
            with self.subTest(identity=identity):
                self.assertEqual(self.premium_response(self.headers(identity)).status_code, expected)

    def test_claimed_tier_and_org_id_cannot_override_database_identity(self):
        headers = self.headers('1', org_id=3, subscription_tier='enterprise')
        self.assertEqual(self.premium_response(headers).status_code, 403)

    def test_tier_changes_take_effect_without_issuing_a_new_token(self):
        headers = self.headers()
        self.assertEqual(self.premium_response(headers).status_code, 403)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("UPDATE organizations SET subscription_tier='pro' WHERE id=1")
        self.assertEqual(self.premium_response(headers).status_code, 200)
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute("UPDATE organizations SET subscription_tier='unknown' WHERE id=1")
        self.assertEqual(self.client.get('/api/findings', headers=headers).status_code, 403)

    def test_storage_error_fails_closed_without_creating_database(self):
        # Simulate the file disappearing after the before_request readiness check.
        with patch.object(self.module, 'database_ready', return_value=True):
            os.remove(self.module.DB_FILE)
            with self.assertLogs(self.module.app.logger, level='ERROR'):
                response = self.client.get('/api/findings', headers=self.headers())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json['error'], 'Workspace access could not be verified. Try again later.')
        self.assertFalse(Path(self.module.DB_FILE).exists())

    def test_bridge_ownership_checks_still_run_before_tier_checks(self):
        with sqlite3.connect(self.module.DB_FILE) as conn:
            conn.execute(
                "INSERT INTO organizations(id,name,owner_user_id,subscription_tier) "
                "VALUES(-1,'Bridge fixture','fixture_owner','enterprise')",
            )
        with patch.dict(os.environ, {'VATA_AUTH_BRIDGE_ENABLED': '1'}):
            for owner, expected in (('fixture_owner', 200), ('other_owner', 403)):
                with self.subTest(owner=owner):
                    headers = self.headers('-1', bridge=True, owner_user_id=owner)
                    self.assertEqual(self.client.get('/api/findings', headers=headers).status_code, expected)
            self.assertEqual(self.client.get('/api/findings', headers=self.headers('-1')).status_code, 403)

    def test_readiness_remains_public(self):
        self.assertEqual(self.client.get('/health').status_code, 200)


if __name__ == '__main__':
    unittest.main()
