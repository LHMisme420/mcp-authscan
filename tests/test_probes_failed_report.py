from mcp_authscan.authorization import ScanMetadata


def test_no_records_omits_failed_line():
    m = ScanMetadata(scope="x", probes_attempted=0, probes_passed=0, probes_failed=None, probes_not_observed=0)
    assert "Probes Failed" not in m.format_block()


def test_source_scan_keeps_failed_count():
    m = ScanMetadata(scope="x", probes_attempted=3, probes_passed=1, probes_failed=2, probes_not_observed=0)
    b = m.format_block()
    assert "Probes Failed: 2" in b
