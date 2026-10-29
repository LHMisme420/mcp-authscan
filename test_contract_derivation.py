#!/usr/bin/env python3
"""Test that derives expected probe counts from contract and verifies against actual run.

Contract:
- 9 declared probes (in_scope)
- 9 built probes; none is NOT_IMPLEMENTED (since probe set 2026.10.29)
- Probes 7-8 (pkce-s256, redirect-uri-exact) need a client. Since probe set 2026.10.30 the
  client comes from dynamic registration at the advertised registration_endpoint, else from
  MCPAUTHSCAN_CLIENT_ID/MCPAUTHSCAN_REDIRECT_URI, else the probe is EXCLUDED. This fixture
  answers POST /register with 401 invalid_request and this run sets no env client, so both are
  EXCLUDED: 7 "No client_id to build an authorization request", 8 "No registered redirect_uri
  to compare against", each with the detail "Dynamic client registration unavailable:
  registration returned HTTP 401 error=invalid_request", and the client registration report
  says no client was registered by this run (probe set 2026.11.02).

When scanning a server:
- attempted = PASS + FAIL + NOT_OBSERVED
- attempted + EXCLUDED + NOT_IMPLEMENTED = in_scope (9)
- coverage = (PASS + FAIL) / in_scope, the declared set, not the probes that ran
- Probes 1-6, 9 should reach verdicts (PASS or FAIL depending on vulnerability)
"""
import os
import sys
import time
import threading

# This derivation is for a run without client credentials; ignore any set in the shell.
for _var in ("MCPAUTHSCAN_CLIENT_ID", "MCPAUTHSCAN_CLIENT_SECRET", "MCPAUTHSCAN_REDIRECT_URI"):
    os.environ.pop(_var, None)

# Force use of local source
sys.path.insert(0, '/home/claude/lhmisme420/mcp-authscan')

# MUST SET BEFORE IMPORTING monolith to affect the global
import mcp_authscan.monolith as monolith_module
monolith_module.ALLOW_PRIVATE_TARGETS = True
# main() sets the same flag on oauth_probes_v2, which has no module default; mirror it here.
import mcp_authscan.oauth_probes_v2 as oauth_probes_v2_module
oauth_probes_v2_module.ALLOW_PRIVATE_TARGETS = True

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
print("  Built probes: 9; NOT_IMPLEMENTED: 0")
print("  Probes 7-8 need a client: registration refused (401) and no env client, so EXCLUDED")
print()
print("For any server:")
print("  - Probes 1-6, 9 should reach verdicts (PASS or FAIL)")
print("  - Probes 7-8 should be EXCLUDED (no client credentials), never NOT_IMPLEMENTED")
print()
print("Expected counts dict:")
print("  in_scope: 9")
print("  attempted: 7 (in_scope - excluded - not_implemented = PASS + FAIL + NOT_OBSERVED)")
print("  PASS: variable (depends on compliance)")
print("  FAIL: variable (depends on vulnerabilities)")
print("  EXCLUDED: 2 (probes 7-8, no client credentials)")
print("  NOT_IMPLEMENTED: 0")
print("  coverage: (PASS + FAIL) / 9")
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
    expected_excluded_names = ["pkce-s256", "redirect-uri-exact"]
    expected_not_implemented = 0
    expected_not_implemented_names = []
    expected_attempted = expected_in_scope - expected_excluded - expected_not_implemented  # = 7
    expected_excluded_detail = ("Dynamic client registration unavailable: "
                                "registration returned HTTP 401 error=invalid_request")
    expected_client_report = {"client_registered": False, "client_source": "none",
                              "client_removal": "no client was registered by this run",
                              "client_deleted": None,
                              # a 401 is not a redirect refusal: only the first candidate is tried
                              "redirect_candidates_tried": [
                                  {"redirect_uri": "http://localhost/mcp-authscan/callback",
                                   "result": "refused, HTTP 401 error=invalid_request"}]}
    
    print("Contract expectations:")
    print(f"  In-scope probes: {expected_in_scope}")
    print(f"  Attempted: {expected_attempted} (in_scope - excluded - not_implemented)")
    print(f"  EXCLUDED: {expected_excluded}")
    print(f"  NOT_IMPLEMENTED: {expected_not_implemented} {expected_not_implemented_names}")
    print()
    
    # Verify against actual
    actual_attempted = probe_status.get('attempted', 0)
    actual_excluded = probe_status.get('excluded', 0)
    actual_not_implemented = probe_status.get('not_implemented', 0)
    actual_not_implemented_names = [r.name for r in oauth_records if r.status == "NOT_IMPLEMENTED"]
    actual_excluded_names = [r.name for r in oauth_records if r.status == "EXCLUDED"]
    actual_excluded_details = [r.detail for r in oauth_records if r.status == "EXCLUDED"]
    client_reports = oauth_probes_v2_module.CLIENT_REPORTS
    client_report_ok = (len(client_reports) == 1 and all(
        client_reports[0].get(k) == v for k, v in expected_client_report.items()))
    from mcp_authscan.counts import count_probes, coverage
    counts = count_probes(oauth_records)
    actual_coverage = coverage(counts)
    expected_coverage = (counts["PASS"] + counts["FAIL"]) / float(expected_in_scope)
    
    print("Verification:")
    print(f"  ✓ Attempted: {actual_attempted} == {expected_attempted}? {actual_attempted == expected_attempted}")
    print(f"  ✓ EXCLUDED: {actual_excluded} == {expected_excluded}? {actual_excluded == expected_excluded}")
    print(f"  ✓ EXCLUDED names: {actual_excluded_names} == {expected_excluded_names}? {actual_excluded_names == expected_excluded_names}")
    print(f"  ✓ EXCLUDED details name the registration outcome: {actual_excluded_details}? {actual_excluded_details == [expected_excluded_detail] * 2}")
    print(f"  ✓ client registration report: {client_reports}? {client_report_ok}")
    print(f"  ✓ NOT_IMPLEMENTED: {actual_not_implemented_names} == {expected_not_implemented_names}? {actual_not_implemented_names == expected_not_implemented_names}")
    attempted_partition = counts["PASS"] + counts["FAIL"] + counts["NOT_OBSERVED"]
    print(f"  ✓ attempted == PASS + FAIL + NOT_OBSERVED: {counts['attempted']} == {attempted_partition}? {counts['attempted'] == attempted_partition}")
    print(f"  ✓ coverage over declared set: {actual_coverage:.4f} == {expected_coverage:.4f}? {actual_coverage == expected_coverage}")
    print()
    
    # Sanity check: attempted + excluded + not_implemented should equal in_scope
    actual_in_scope = actual_attempted + actual_excluded + actual_not_implemented
    print(f"Sanity check (attempted + excluded + not_implemented = in_scope):")
    print(f"  {actual_attempted} + {actual_excluded} + {actual_not_implemented} = {actual_in_scope} (expected {expected_in_scope})")
    print()
    
    if (actual_attempted == expected_attempted and actual_excluded == expected_excluded
            and actual_not_implemented == expected_not_implemented
            and actual_not_implemented_names == expected_not_implemented_names
            and actual_excluded_names == expected_excluded_names
            and actual_excluded_details == [expected_excluded_detail] * 2
            and client_report_ok
            and actual_in_scope == expected_in_scope
            and counts["in_scope"] == expected_in_scope
            and counts["attempted"] == attempted_partition
            and actual_coverage == expected_coverage):
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
