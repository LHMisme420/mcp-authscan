import unittest
from unittest import mock

from mcp_authscan import oauth_probes_v2 as probes


class TokenCorsNoCredentialTest(unittest.TestCase):

    def test_no_client_credential_excludes_without_sending(self):
        sent = []

        def fake_guard(request):
            sent.append(request)
            return 400, {}, b'{"error": "invalid_request"}'

        with (
            mock.patch.object(probes, "_client_creds", return_value=(None, None, None)),
            mock.patch.object(probes, "_egress_guard", side_effect=fake_guard),
        ):
            rec = probes.probe_token_cors("http://127.0.0.1:9004/token")

        self.assertEqual([], sent, "token-cors sent a request with no credential")
        self.assertEqual("EXCLUDED", rec.status)
        reason = getattr(rec, "limitation", "") or getattr(rec, "detail", "") or ""
        self.assertIn("credential", reason)

