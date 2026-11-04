import unittest

from mcp_authscan import monolith
from tests.fixtures.derived_metadata_server import start


class DerivedMetadataTest(unittest.TestCase):
    def setUp(self):
        self.server, self.port = start()
        self.base = "http://127.0.0.1:%d" % self.port

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_host_form_found_when_path_form_404s(self):
        endpoints, info = monolith.discover_oauth_endpoints(self.base + "/mcp", allow_private=True)
        self.assertIsNotNone(endpoints)
        self.assertEqual(info["method"], "RFC 9728 derived")
        self.assertEqual(endpoints["token"], self.base + "/token")
        self.assertEqual(endpoints["authorize"], self.base + "/authorize")


