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
    build_batch_dict, compute_exit_code, load_targets, scan_one,
)
from mcp_authscan.report import SecurityReport
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
