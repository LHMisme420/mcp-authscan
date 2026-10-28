"""Test token-cors probe handling of 5xx and absent ACAO."""

import unittest
from unittest.mock import patch, MagicMock
from mcp_authscan.oauth_probes_v2 import probe_token_cors

class TestTokenCors5xx(unittest.TestCase):
    """Test cases for token-cors probe verdict logic."""
    
    @patch('mcp_authscan.oauth_probes_v2.urlopen')
    def test_token_cors_501_no_acao(self, mock_urlopen):
        """501 with no ACAO should return NOT_OBSERVED, not PASS."""
        mock_resp = MagicMock()
        mock_resp.headers = {}  # No ACAO header
        mock_resp.read.return_value = b"Internal Server Error"
        mock_resp.status = 501
        mock_resp.code = 501
        
        # Simulate HTTPError for 501
        from urllib.error import HTTPError
        error = HTTPError("http://test.com", 501, "Not Implemented", {}, None)
        error.headers = {}
        error.read = lambda: b"Internal Server Error"
        error.code = 501
        mock_urlopen.side_effect = error
        
        result = probe_token_cors("http://test.com/token")
        
        self.assertEqual(result.status, "NOT_OBSERVED", 
                        "501 with no ACAO should be NOT_OBSERVED, got: " + result.status)
    
    @patch('mcp_authscan.oauth_probes_v2.urlopen')
    def test_token_cors_200_wildcard_acao(self, mock_urlopen):
        """200 with wildcard ACAO should return FAIL."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Access-Control-Allow-Origin": "*"}
        mock_resp.read.return_value = b'{"access_token": "test"}'
        mock_resp.status = 200
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *args: None
        mock_urlopen.return_value = mock_resp
        
        result = probe_token_cors("http://test.com/token")
        
        self.assertEqual(result.status, "FAIL",
                        "Wildcard ACAO should be FAIL, got: " + result.status)
    
    @patch('mcp_authscan.oauth_probes_v2.urlopen')
    def test_token_cors_200_no_acao(self, mock_urlopen):
        """200 with no ACAO should return NOT_OBSERVED (endpoint not configured for CORS)."""
        mock_resp = MagicMock()
        mock_resp.headers = {}  # No ACAO header
        mock_resp.read.return_value = b'{"token_type": "Bearer"}'
        mock_resp.status = 200
        mock_resp.__enter__ = lambda self: self
        mock_resp.__exit__ = lambda self, *args: None
        mock_urlopen.return_value = mock_resp
        
        result = probe_token_cors("http://test.com/token")
        
        self.assertEqual(result.status, "NOT_OBSERVED",
                        "200 with no ACAO should be NOT_OBSERVED (not PASS), got: " + result.status)

if __name__ == '__main__':
    unittest.main()
