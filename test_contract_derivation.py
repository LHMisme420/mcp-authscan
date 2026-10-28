#!/usr/bin/env python3
"""Test that derives expected probe counts from contract and verifies against actual run.

Updated Contract (from PROBE_CONTRACT.md):
- 9 total probes
- 7 in-scope (probes 1-6, 9: issuer-identity, resource-binding, token-cache-control, token-cors, jwks-keys, password-grant, client-auth)
- 2 excluded/out-of-scope (probes 7-8: pkce-s256, redirect-uri-exact) -> EXCLUDED expected

When scanning a server:
- All 9 probes are defined (attempted in the contract sense)
- Probes 7-8 are EXCLUDED (unmet prerequisites)
- Probes 1-6, 9 should reach verdicts (PASS or FAIL depending on vulnerability)
"""
import sys
import time
import threading

# Force use of local source
sys.path.insert(0, '/home/claude/lhmisme420/mcp-authscan')

# MUST SET BEFORE IMPORTING monolith to affect the global
import mcp_authscan.monolith as monolith_module
monolith_module.ALLOW_PRIVATE_TARGETS = True

from mcp_authscan.monolith import scan_live_server

def start_fixture_server(port=9002):
    """Start the test fixture server in background."""
    def run_server():
        try:
            from tests.test_fixture_with_findings import FindingsHandler
            from http.server import HTTPServer
            server = HTTPServer(("127.0.0.1", port), FindingsHandler)
            server.serve_forever()
        except Exception as e:
            print(f"[!] Fixture server error: {e}", file=sys.stderr)
    
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    time.sleep(1)  # Give server time to start
    return thread

print("=" * 70)
print("DERIVING EXPECTED COUNTS FROM UPDATED PROBE_CONTRACT.md")
print("=" * 70)
print()
print("Contract specifies:")
print("  Total probes: 9")
print("  In-scope probes (testable on any server): 7 (probes 1-6, 9)")
print("  Out-of-scope/EXCLUDED probes (requires client flow): 2 (probes 7-8)")
print()
print("For any server:")
print("  - Probes 1-6, 9 should reach verdicts (PASS or FAIL)")
print("  - Probes 7-8 should be EXCLUDED (unmet prerequisites)")
print()
print("Expected counts dict:")
print("  in_scope: 9")
print("  attempted: 7 (in_scope - excluded)")
print("  PASS: variable (depends on compliance)")
print("  FAIL: variable (depends on vulnerabilities)")
print("  EXCLUDED: 2 (probes 7-8)")
print("  NOT_OBSERVED: variable (depends on endpoint availability)")
print()

print("=" * 70)
print("RUNNING SCAN AGAINST FIXTURE ON PORT 9002")
print("=" * 70)
print()

# Start fixture server
print("[*] Starting fixture server on 127.0.0.1:9002...")
server_thread = start_fixture_server(port=9002)

try:
    # Scan the fixture
    print("[*] Running scan against http://127.0.0.1:9002/mcp...")
    findings, reachable, probe_status, discovery_info, (oauth_records, probe_results) = scan_live_server(
        "http://127.0.0.1:9002/mcp"
    )
    
    print()
    print("=" * 70)
    print("ACTUAL RESULTS")
    print("=" * 70)
    print()
    print("Probe status dict:")
    for key, value in probe_status.items():
        print(f"  {key}: {value}")
    print()
    
    # Derive from contract
    expected_in_scope = 9
    expected_excluded = 2
    expected_attempted = expected_in_scope - expected_excluded  # = 7
    
    print("Contract expectations:")
    print(f"  In-scope probes: {expected_in_scope}")
    print(f"  Attempted: {expected_attempted} (in_scope - excluded)")
    print(f"  EXCLUDED: {expected_excluded}")
    print()
    
    # Verify against actual
    actual_attempted = probe_status.get('attempted', 0)
    actual_excluded = probe_status.get('excluded', 0)
    
    print("Verification:")
    print(f"  ✓ Attempted: {actual_attempted} == {expected_attempted}? {actual_attempted == expected_attempted}")
    print(f"  ✓ EXCLUDED: {actual_excluded} == {expected_excluded}? {actual_excluded == expected_excluded}")
    print()
    
    # Sanity check: attempted + excluded should equal in_scope
    actual_in_scope = actual_attempted + actual_excluded
    print(f"Sanity check (attempted + excluded = in_scope):")
    print(f"  {actual_attempted} + {actual_excluded} = {actual_in_scope} (expected {expected_in_scope})")
    print()
    
    if actual_attempted == expected_attempted and actual_excluded == expected_excluded:
        print("✓ SUCCESS: Actual counts match contract derivation!")
    else:
        print("✗ FAILURE: Actual counts do NOT match contract!")
        sys.exit(1)
    
    print()
    print("OAuth records returned:")
    print(f"  Count: {len(oauth_records)}")
    for i, record in enumerate(oauth_records, 1):
        probe_id = getattr(record, 'probe_id', '?')
        name = getattr(record, 'name', '?')
        status = getattr(record, 'status', '?')
        print(f"  {i}. {probe_id}: {name} -> {status}")

except Exception as e:
    print(f"[!] Error during scan: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

finally:
    print()
    print("=" * 70)
    print("Done")
    print("=" * 70)
