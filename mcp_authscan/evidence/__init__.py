"""MCP AuthScan evidence protocol.

Implementations of the public specifications in schemas/:
security-state-v1 (state.py), observation-v1 (observation.py),
boundary-delta-v1 (delta.py) and boundary-ledger-v1 (ledger.py).

No network I/O anywhere in this package. File I/O is confined to
ledger.read_ledger / ledger.append_observation. The only scanner import is
mcp_authscan.surface (stdlib-only), which supplies the canonical
serialization and surface_digest.
"""
