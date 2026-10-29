"""Token issuance must fail probes, not disappear as NOT_OBSERVED."""
from io import BytesIO
import json
import unittest
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

from mcp_authscan.oauth_probes_v2 import probe_client_auth, probe_password_grant


class TokenVerdictTests(unittest.TestCase):
    def evaluate(self, probe, status, payload):
        body = json.dumps(payload).encode()
        with patch('mcp_authscan.oauth_probes_v2.urlopen') as request:
            if status >= 400:
                request.side_effect = HTTPError(
                    'https://fixture.example.test/token', status, 'fixture', {}, BytesIO(body))
            else:
                response = MagicMock()
                response.status = status
                response.read.return_value = body
                request.return_value.__enter__.return_value = response
            return probe('https://fixture.example.test/token')

    def test_actual_token_issuance_is_high_failure_with_real_http_status(self):
        for probe in (probe_password_grant, probe_client_auth):
            with self.subTest(probe=probe.__name__):
                record = self.evaluate(probe, 200, {'access_token': 'synthetic-fixture-token'})
                self.assertEqual((record.status, record.severity, record.http_status),
                                 ('FAIL', 'HIGH', 200))

    def test_empty_or_ambiguous_success_does_not_establish_token_issuance(self):
        for probe in (probe_password_grant, probe_client_auth):
            for payload in ({}, {'access_token': ''}, {'access_token': 5},
                            {'access_token': 'synthetic', 'error': 'invalid_request'}):
                with self.subTest(probe=probe.__name__, payload=payload):
                    self.assertEqual(self.evaluate(probe, 200, payload).status, 'NOT_OBSERVED')

    def test_explicit_rejections_pass_only_on_client_error_responses(self):
        for probe, error in ((probe_password_grant, 'unsupported_grant_type'),
                             (probe_client_auth, 'invalid_client')):
            with self.subTest(probe=probe.__name__):
                record = self.evaluate(probe, 400, {'error': error})
                self.assertEqual((record.status, record.http_status), ('PASS', 400))
                self.assertEqual(self.evaluate(probe, 503, {'error': error}).status,
                                 'NOT_OBSERVED')

    def test_protected_error_with_token_shaped_body_is_not_a_finding(self):
        for probe in (probe_password_grant, probe_client_auth):
            with self.subTest(probe=probe.__name__):
                record = self.evaluate(probe, 403, {'access_token': 'synthetic-error-marker'})
                self.assertEqual(record.status, 'NOT_OBSERVED')
                self.assertIsNone(record.severity)
import pytest
@pytest.fixture(autouse=True)
def _allow_test_host(monkeypatch):
    monkeypatch.setattr("mcp_authscan.monolith.ALLOWED_HOSTS", {"test.com"})
    monkeypatch.setattr("mcp_authscan.oauth_probes_v2.assert_url_is_fetchable", lambda *a, **k: None)
    monkeypatch.setattr("mcp_authscan.monolith.ALLOWED_HOSTS", {"fixture.example.test"})
