import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.client import IncompleteRead
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError

from mcp_authscan.authorized_scan import main, scan_endpoint, validate_target
from mcp_authscan.cors import MAX_BODY


class EndpointHandler(BaseHTTPRequestHandler):
    requests_seen = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        size = int(self.headers.get("Content-Length", 0))
        self.server.last_payload = json.loads(self.rfile.read(size))
        self.do_GET()

    def do_GET(self):
        self.requests_seen.append((self.path, dict(self.headers)))
        status = {"/protected": 401, "/forbidden": 403, "/redirect": 302,
                  "/missing": 404}.get(self.path, 200)
        self.send_response(status)
        if self.path == "/redirect":
            self.send_header("Location", "/outside-authorization")
        origin = self.headers.get("Origin", "")
        self.send_header("Access-Control-Allow-Origin",
                         origin if self.path in {"/private", "/protected", "/forbidden"}
                         else "*")
        self.send_header("Set-Cookie", "session=synthetic; HttpOnly")
        content_type = "text/event-stream" if self.path == "/sse" else "application/json"
        self.send_header("Content-Type", content_type)
        if self.path == "/encoded":
            self.send_header("Content-Encoding", "gzip")
        body = (b'{"user":{"email":"private@example.test"}}'
                if self.path in {"/private", "/protected", "/forbidden"}
                else b'{"result":{"tools":[{"name":"public-search"}]}}')
        if self.path == "/large":
            body = b"x" * (MAX_BODY + 100)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class AuthorizedScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), EndpointHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        EndpointHandler.requests_seen.clear()

    def test_public_200_and_wildcard_are_not_findings(self):
        result = scan_endpoint(self.base + "/public")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "completed")
        for path, headers in EndpointHandler.requests_seen:
            self.assertEqual(path, "/public")
            self.assertNotIn("Cookie", headers)
            self.assertNotIn("Authorization", headers)

    def test_protected_responses_are_not_findings_even_with_private_body(self):
        for path in ("/protected", "/forbidden"):
            with self.subTest(path=path):
                result = scan_endpoint(self.base + path)
                self.assertEqual(result["findings"], [])
                self.assertTrue(all(probe["protected"] for probe in result["probes"]))
                self.assertFalse(result["cors"]["is_finding"])

    def test_sensitive_reflection_is_reviewable_and_body_is_not_saved(self):
        result = scan_endpoint(self.base + "/private")
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(result["cors"]["reflected"])
        self.assertTrue(all(finding["review_required"] for finding in result["findings"]))
        self.assertNotIn("private@example.test", json.dumps(result))
        self.assertNotIn("session=synthetic", json.dumps(result))

    def test_redirects_are_not_followed_and_are_incomplete(self):
        result = scan_endpoint(self.base + "/redirect")
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["findings"], [])
        self.assertEqual([path for path, _ in EndpointHandler.requests_seen],
                         ["/redirect", "/redirect"])

    def test_sse_large_and_missing_responses_are_not_silently_passed(self):
        for path in ("/sse", "/large", "/missing", "/encoded"):
            with self.subTest(path=path):
                result = scan_endpoint(self.base + path)
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(result["findings"], [])

    def test_post_is_only_tools_list(self):
        result = scan_endpoint(self.base + "/public", method="POST")
        self.assertEqual(self.server.last_payload,
                         {"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        self.assertEqual(result["findings"], [])

    def test_transport_errors_are_reported_without_sensitive_exception_text(self):
        opener = Mock()
        opener.open.side_effect = URLError("do-not-store-this")
        result = scan_endpoint(self.base + "/public", opener=opener)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(len(result["errors"]), 2)
        self.assertNotIn("do-not-store-this", json.dumps(result))

    def test_interrupted_responses_and_timeouts_are_incomplete(self):
        for error in (IncompleteRead(b"private-value"), TimeoutError("private-value")):
            with self.subTest(error=type(error).__name__):
                opener = Mock()
                opener.open.side_effect = error
                result = scan_endpoint(self.base + "/public", opener=opener)
                self.assertEqual(result["status"], "incomplete")
                self.assertEqual(len(result["errors"]), 2)
                self.assertEqual(result["findings"], [])
                self.assertNotIn("private-value", json.dumps(result))

    def test_invalid_targets(self):
        for target in ("file:///etc/passwd", "https://user:pass@example.test",
                       "https://example.test/?token=synthetic", "https://example.test/#x",
                       "https://example.test:invalid", "https://example.test:0",
                       "https://example.test/\nheader", "https://example.test\\other"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                validate_target(target)

    def test_authorization_and_all_targets_validated_before_any_requests(self):
        cases = [
            ["--target", self.base + "/public"],
            ["--authorized", "--target", self.base + "/public", "--target", "file:///tmp/x"],
            ["--authorized", "--target", self.base, "--timeout", "0"],
        ]
        with patch("mcp_authscan.authorized_scan.scan_endpoint") as scan:
            for args in cases:
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        main(args)
                    self.assertEqual(error.exception.code, 2)
            scan.assert_not_called()

    def test_cli_saves_report_deduplicates_targets_and_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "report.json"
            args = ["--authorized", "--target", self.base + "/public",
                    "--target", self.base + "/public", "--output", str(output)]
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 0)
                report = json.loads(output.read_text())
                self.assertEqual(len(report["results"]), 1)
                self.assertEqual(report["finding_count"], 0)
                with self.assertRaises(SystemExit):
                    main(args)
            self.assertEqual(json.loads(output.read_text()), report)
            self.assertEqual(len(EndpointHandler.requests_seen), 2)

    def test_cli_exit_codes_for_findings_and_incomplete_scan(self):
        for path, expected in (("/private", 1), ("/redirect", 2)):
            with self.subTest(path=path), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--authorized", "--target", self.base + path]), expected)


if __name__ == "__main__":
    unittest.main()
