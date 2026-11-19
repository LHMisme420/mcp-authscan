"""MCP AuthScan evidence protocol.

Pure implementations of the public specifications in
schemas/: security-state-v1 (state.py), observation-v1 (observation.py),
boundary-delta-v1 (delta.py); plus the surface state (state.py).

Nothing in this package performs network or file I/O. The only scanner
import is mcp_authscan.surface (stdlib-only; used for the surface state).
"""
