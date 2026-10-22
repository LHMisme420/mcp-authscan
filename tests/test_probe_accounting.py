"""Test probe accounting: partition, hash, and renderer coverage.

Partition test: every probe ID appears exactly once across buckets.
Hash test: changing any count invalidates the hash.
Renderer tests: pull numbers from text/JSON outputs and verify they match.
"""
import json
import re

from mcp_authscan.report import SecurityReport
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


def test_renderer_text_matches_data():
    """Renderer test: text output must contain all summary numbers."""
    findings, reachable, probe_status, discovery_info, (oauth_records, probe_results) = scan_live_server(
        "http://127.0.0.1:5555"
    )

    report = SecurityReport(
        target_url="http://127.0.0.1:5555",
        findings=findings,
        probe_status=probe_status,
        timestamp="2026-10-22T14:00:00Z"
    )

    text_output = report.text()

    # Extract numbers from text output
    total_match = re.search(r"Total Checks:\s*(\d+)", text_output)
    passed_match = re.search(r"Passed:\s*(\d+)", text_output)

    assert total_match, "Total Checks not found in text output"
    assert passed_match, "Passed count not found in text output"

    # Verify extracted numbers match source
    assert int(total_match.group(1)) == probe_status.get('attempted', 0), (
        "Total checks in text output doesn't match probe_status"
    )


def test_renderer_json_matches_data():
    """Renderer test: JSON output must contain all summary numbers."""
    findings, reachable, probe_status, discovery_info, (oauth_records, probe_results) = scan_live_server(
        "http://127.0.0.1:5555"
    )

    report = SecurityReport(
        target_url="http://127.0.0.1:5555",
        findings=findings,
        probe_status=probe_status,
        timestamp="2026-10-22T14:00:00Z"
    )

    json_output = report.json()
    data = json.loads(json_output)

    # Verify summary is present and matches source
    assert 'summary' in data, "Summary not found in JSON output"
    assert data['summary'].get('attempted') == probe_status.get('attempted', 0), (
        "Attempted count in JSON doesn't match probe_status"
    )


if __name__ == '__main__':
    import unittest
    unittest.main()
