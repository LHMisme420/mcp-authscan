"""Fixture: _egress_guard must refuse out-of-scope URLs and raise EgressRefusalError."""
import sys
sys.path.insert(0, '/home/lhmisme/mcp-authscan')

from mcp_authscan.oauth_probes_v2 import _egress_guard, EgressRefusalError
from urllib.request import Request

# Test 1: In-scope URL (global, routable)
print("Test 1: In-scope URL (should not raise)")
try:
    req = Request("https://example.com/token")
    # This will fail to connect but should not fail the scope check
    status, headers, body = _egress_guard(req, timeout=1)
    print("✗ Should have failed to connect (no timeout or connection available)")
except EgressRefusalError as e:
    print("✗ Guard incorrectly refused in-scope URL: %s" % e)
    sys.exit(6)
except Exception as e:
    print("✓ In-scope URL passed scope check (failed later with: %s)" % type(e).__name__)

# Test 2: Out-of-scope URL (private address - SSRF risk)
print("\nTest 2: Out-of-scope URL (should raise EgressRefusalError)")
try:
    req = Request("http://169.254.169.254/latest/meta-data/iam/security-credentials/")
    status, headers, body = _egress_guard(req)
    print("✗ Guard failed to refuse private address (169.254.169.254)")
    sys.exit(1)
except EgressRefusalError as e:
    print("✓ Guard correctly refused private address: %s" % e)
    sys.exit(0)
except Exception as e:
    print("✗ Wrong exception type: %s: %s" % (type(e).__name__, e))
    sys.exit(2)
