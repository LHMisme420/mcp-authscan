"""Scope enforcement: probe evil.example.com with scope=api.example.com → exit 6."""
import sys
sys.path.insert(0, '/home/lhmisme/mcp-authscan')

# Set scope to api.example.com
import mcp_authscan.monolith
mcp_authscan.monolith.SCOPE = "api.example.com"

# Probe unauthorized domain - should raise EgressRefusalError (propagates to main → exit 6)
from mcp_authscan.oauth_probes_v2 import probe_token_cors
result = probe_token_cors("http://evil.example.com/token")

# If we reach here, the guard failed
print("✗ Guard failed - no exception raised")
sys.exit(1)
