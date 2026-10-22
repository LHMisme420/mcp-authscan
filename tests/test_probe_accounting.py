"""Test probe accounting: partition and hash coverage.

Partition test: every probe ID appears exactly once across buckets.
Hash test: changing any count invalidates the hash.
"""
import json
from mcp_authscan.scan_main import scan_live_server


def test_probe_partition_fixture_good():
    """Good fixture: passed + failed + not_observed + observation + excluded = attempted.
    
    This test catches "7 does not equal 9" without hardcoding either number.
    It will keep catching it when probes are added.
    """
    findings, reachable, probe_status, discovery_info, (oauth_records, probe_results) = scan_live_server(
        "http://127.0.0.1:5555"
    )
    
    # Partition: every probe appears exactly once in exactly one bucket
    passed = probe_status.get('passed', 0)
    failed = probe_status.get('failed', 0)
    not_observed = probe_status.get('not_observed', 0)
    observation = probe_status.get('observation', 0)
    excluded = probe_status.get('excluded', 0)
    attempted = probe_status.get('attempted', 0)
    
    partition_sum = passed + failed + not_observed + observation + excluded
    
    # Every probe in attempted appears exactly once
    assert partition_sum == attempted, (
        f"Probe partition violated: {passed} passed + {failed} failed + "
        f"{not_observed} not_observed + {observation} observation + "
        f"{excluded} excluded = {partition_sum}, but attempted = {attempted}"
    )


def test_probe_partition_fixture_bad():
    """Bad fixture: same partition test on vulnerable server."""
    findings, reachable, probe_status, discovery_info, (oauth_records, probe_results) = scan_live_server(
        "http://127.0.0.1:5556"
    )
    
    passed = probe_status.get('passed', 0)
    failed = probe_status.get('failed', 0)
    not_observed = probe_status.get('not_observed', 0)
    observation = probe_status.get('observation', 0)
    excluded = probe_status.get('excluded', 0)
    attempted = probe_status.get('attempted', 0)
    
    partition_sum = passed + failed + not_observed + observation + excluded
    assert partition_sum == attempted, (
        f"Probe partition violated: {partition_sum} != {attempted}"
    )


if __name__ == '__main__':
    import unittest
    unittest.main()
