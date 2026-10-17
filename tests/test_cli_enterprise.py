#!/usr/bin/env python3
"""Tests for the enterprise CLI surface: target loading, fleet aggregation,
and --fail-on exit-code gating."""
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp_authscan.cli import (
    EXIT_FINDINGS, EXIT_OK, EXIT_SCAN_ERROR,
    build_batch_dict, build_batch_text, compute_exit_code, load_targets, scan_one,
)
from mcp_authscan.report import SecurityReport, build_sarif
from mcp_authscan.scanner import Check, RiskLevel


def _check(risk, passed):
    return Check("n", "d", "/e", "GET", risk, passed, "det", "rem")


def _ok_result(target, checks):
    return {"target": target, "status": "ok", "checks": checks,
            "report": SecurityReport(checks, target)}


class _Locked(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _h(self):
        self.send_response(401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_GET = do_POST = do_HEAD = _h


class LoadTargetsTests(unittest.TestCase):
    def test_merges_urls_and_file_and_dedupes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "targets.txt")
            with open(path, "w") as f:
                f.write("# comment\nhttp://a\nhttp://b\n\nhttp://a\n")
            got = load_targets(["http://a", "http://c"], path)
        self.assertEqual(got, ["http://a", "http://c", "http://b"])

    def test_empty(self):
        self.assertEqual(load_targets([], None), [])


class ExitCodeTests(unittest.TestCase):
    def test_critical_meets_default_threshold(self):
        results = [_ok_result("t", [_check(RiskLevel.CRITICAL, False)])]
        self.assertEqual(compute_exit_code(results, "critical"), EXIT_FINDINGS)

    def test_high_below_critical_threshold_is_ok(self):
        results = [_ok_result("t", [_check(RiskLevel.HIGH, False)])]
        self.assertEqual(compute_exit_code(results, "critical"), EXIT_OK)

    def test_high_meets_high_threshold(self):
        results = [_ok_result("t", [_check(RiskLevel.HIGH, False)])]
        self.assertEqual(compute_exit_code(results, "high"), EXIT_FINDINGS)

    def test_fail_on_none_never_fails_on_findings(self):
        results = [_ok_result("t", [_check(RiskLevel.CRITICAL, False)])]
        self.assertEqual(compute_exit_code(results, "none"), EXIT_OK)

    def test_scan_error_sets_error_exit(self):
        results = [{"target": "t", "status": "error", "error": "unreachable"}]
        self.assertEqual(compute_exit_code(results, "critical"), EXIT_SCAN_ERROR)

    def test_findings_outrank_errors(self):
        results = [
            _ok_result("t1", [_check(RiskLevel.CRITICAL, False)]),
            {"target": "t2", "status": "error", "error": "x"},
        ]
        self.assertEqual(compute_exit_code(results, "critical"), EXIT_FINDINGS)


class BatchDictTests(unittest.TestCase):
    def test_aggregates_counts_and_entries(self):
        results = [
            _ok_result("http://t1", [_check(RiskLevel.CRITICAL, False),
                                     _check(RiskLevel.INFO, True)]),
            {"target": "http://t2", "status": "error", "error": "unreachable"},
        ]
        batch = build_batch_dict(results)
        self.assertEqual(batch["summary"]["targets"], 2)
        self.assertEqual(batch["summary"]["scanned"], 1)
        self.assertEqual(batch["summary"]["errors"], 1)
        self.assertEqual(batch["summary"]["critical"], 1)
        self.assertEqual(batch["summary"]["findings"], 1)
        statuses = {e["target"]: e["status"] for e in batch["results"]}
        self.assertEqual(statuses, {"http://t1": "ok", "http://t2": "error"})


class SarifTests(unittest.TestCase):
    def test_only_failed_checks_become_results_with_mapped_levels(self):
        checks = [
            _check(RiskLevel.CRITICAL, False),
            _check(RiskLevel.INFO, True),      # passed -> not emitted
            _check(RiskLevel.MEDIUM, False),
        ]
        doc = build_sarif([("http://t", checks)], tool_version="1.2.3")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "mcp-authscan")
        self.assertEqual(run["tool"]["driver"]["version"], "1.2.3")
        # Two failed checks -> two results; the passed INFO check is excluded.
        self.assertEqual(len(run["results"]), 2)
        levels = sorted(r["level"] for r in run["results"])
        self.assertEqual(levels, ["error", "warning"])
        # Every result carries an artifact-location URI and a rule id.
        for r in run["results"]:
            self.assertTrue(r["ruleId"].startswith("mcp-authscan/"))
            uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            self.assertTrue(uri.startswith("http://t"))

    def test_rules_deduplicated_across_targets(self):
        checks = [_check(RiskLevel.CRITICAL, False)]
        doc = build_sarif([("http://a", checks), ("http://b", list(checks))])
        run = doc["runs"][0]
        self.assertEqual(len(run["results"]), 2)            # one per target
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 1)  # same rule, deduped
        self.assertIn("security-severity",
                      run["tool"]["driver"]["rules"][0]["properties"])


class ReportRenderingTests(unittest.TestCase):
    def test_text_report_renders_sections_and_findings(self):
        checks = [_check(RiskLevel.CRITICAL, False), _check(RiskLevel.INFO, True)]
        text = SecurityReport(checks, "http://t").text()
        self.assertIn("MCP SECURITY SCAN REPORT", text)
        self.assertIn("CRITICAL: 1", text)
        self.assertIn("✗ FAILED", text)
        self.assertIn("✓ PASSED", text)

    def test_batch_text_lists_targets_and_errors(self):
        results = [
            _ok_result("http://t1", [_check(RiskLevel.CRITICAL, False)]),
            {"target": "http://t2", "status": "error", "error": "unreachable"},
        ]
        text = build_batch_text(results)
        self.assertIn("http://t1", text)
        self.assertIn("ERROR - unreachable", text)
        self.assertIn("Total CRITICAL: 1", text)


class ScanOneIntegrationTests(unittest.TestCase):
    def test_scan_one_ok_against_locked_server(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Locked)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            host, port = server.server_address[:2]
            result = scan_one(f"http://{host}:{port}", timeout=5, headers={})
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(compute_exit_code([result], "critical"), EXIT_OK)

    def test_scan_one_unreachable_is_error_not_raise(self):
        # Port 1 is not listening; MCPScanner raises, scan_one captures it.
        result = scan_one("http://127.0.0.1:1", timeout=2, headers={})
        self.assertEqual(result["status"], "error")
        self.assertEqual(compute_exit_code([result], "critical"), EXIT_SCAN_ERROR)


if __name__ == "__main__":
    unittest.main()
