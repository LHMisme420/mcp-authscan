import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from mcp_authscan.cors import (
    CorsResponse, assess_cors, probe_cors, probe_cors_requests,
    probe_cors_urllib, sensitive_user_data,
)
from mcp_authscan.scanner import MCPScanner, RiskLevel


PRIVATE = json.dumps({"user": {"id": 1, "email": "fixture@example.test"}}).encode()
PUBLIC = b'{"jsonrpc":"2.0","result":{"tools":[{"name":"public-search"}]}}'
ORIGINS = ("https://one.invalid", "https://two.example")


class FakeResponse:
    def __init__(self, headers, body=PUBLIC, status=200):
        self.headers, self.body, self.content, self.status, self.status_code = headers, body, body, status, status
        self.request = Mock(headers={})

    def read(self, size):
        return self.body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class CorsPolicyTests(unittest.TestCase):
    def assess(self, headers, body=PUBLIC, status=200):
        return assess_cors([(ORIGINS[0], CorsResponse(headers, body, status))])

    def test_public_token_api_wildcard_is_not_a_finding(self):
        result = self.assess({
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "Authorization",
        })
        self.assertFalse(result.is_finding)
        self.assertEqual(result.severity, "INFO")

    def test_sensitive_wildcard_requires_cookie_or_credentials_evidence(self):
        for extra, expected in (
            ({}, False),
            ({"Set-Cookie": "analytics_id=fixture; Secure"}, False),
            ({"Set-Cookie": "session=fixture; HttpOnly"}, False),
            ({"WWW-Authenticate": "Cookie"}, True),
            ({"Access-Control-Allow-Credentials": "true"}, True),
        ):
            with self.subTest(extra=extra):
                result = self.assess({"Access-Control-Allow-Origin": "*", **extra}, PRIVATE)
                self.assertEqual(result.is_finding, expected)
                self.assertEqual(result.severity, "MEDIUM" if expected else "INFO")
                self.assertNotIn("fixture@example.test", result.details)
                self.assertNotIn("session=fixture", result.details)

    def test_credentials_without_sensitive_data_do_not_flag_wildcard(self):
        result = self.assess({
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "TRUE",
        })
        self.assertFalse(result.is_finding)

    def test_verified_cookie_authentication_qualifies_sensitive_wildcard(self):
        result = assess_cors([(ORIGINS[0], CorsResponse(
            {"Access-Control-Allow-Origin": "*"}, PRIVATE,
            cookie_authenticated=True,
        ))])
        self.assertTrue(result.is_finding)

    def test_requests_verifies_cookie_requirement_without_mutating_session(self):
        session = Mock(verify=True)
        private_response = FakeResponse({"Access-Control-Allow-Origin": "*"}, PRIVATE)
        private_response.request.headers = {"Cookie": "session=fixture"}
        session.request.return_value = private_response
        for status, expected in ((401, True), (200, False)):
            with self.subTest(status=status), patch(
                "requests.request", return_value=FakeResponse({}, PUBLIC, status)
            ) as anonymous_request:
                result = probe_cors_requests("https://fixture.invalid", session=session)
                self.assertEqual(result.is_finding, expected)
                self.assertEqual(anonymous_request.call_args.kwargs["headers"]["Cookie"], "")
                self.assertEqual(private_response.request.headers["Cookie"], "session=fixture")

    def test_error_or_empty_response_does_not_establish_user_data(self):
        for body, status in ((b"", 204), (b'{"error":"Unauthorized"}', 401)):
            result = self.assess({
                "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
            }, body, status)
            self.assertFalse(result.is_finding)

    def test_401_and_403_are_protected_even_with_sensitive_shaped_error_body(self):
        for status in (401, 403):
            with self.subTest(status=status):
                result = self.assess({
                    "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true",
                }, b'{"accessToken":"sensitive-fixture-value"}', status)
                self.assertFalse(result.is_finding)
                self.assertEqual(result.severity, "INFO")
                self.assertIn("protected", result.details)
                self.assertNotIn("sensitive-fixture-value", result.details)

    def test_sensitive_detector_handles_sse_profiles_and_not_schemas(self):
        self.assertTrue(sensitive_user_data(b"data: " + PRIVATE + b"\n\n"))
        self.assertTrue(sensitive_user_data(b'{"SSN":"sensitive-fixture"}'))
        self.assertFalse(sensitive_user_data(b'{"properties":{"access_token":{"type":"string"}}}'))
        self.assertFalse(sensitive_user_data(PUBLIC))

    def test_reflection_requires_two_different_origins(self):
        single = assess_cors([(ORIGINS[0], CorsResponse({"Access-Control-Allow-Origin": ORIGINS[0]}, PRIVATE))])
        self.assertFalse(single.is_finding)
        allowed = assess_cors([
            (origin, CorsResponse({"Access-Control-Allow-Origin": ORIGINS[0]}, PRIVATE))
            for origin in ORIGINS
        ])
        self.assertFalse(allowed.is_finding)

    def test_evidence_from_different_responses_is_not_combined(self):
        result = assess_cors([
            (ORIGINS[0], CorsResponse({
                "Access-Control-Allow-Origin": ORIGINS[0], "Set-Cookie": "session=fixture"
            }, PRIVATE)),
            (ORIGINS[1], CorsResponse({"Access-Control-Allow-Origin": "*"}, PUBLIC)),
        ])
        self.assertFalse(result.is_finding)

    def test_package_public_exports_remain_available(self):
        from mcp_authscan import MCPScanner as ExportedScanner, SecurityReport
        self.assertIs(ExportedScanner, MCPScanner)
        self.assertTrue(callable(SecurityReport))

    def test_arbitrary_reflection_risk_depends_on_data_and_credentials(self):
        for body, credentials, severity, finding in (
            (PUBLIC, False, "INFO", False), (PRIVATE, False, "MEDIUM", True),
            (PRIVATE, True, "HIGH", True),
        ):
            with self.subTest(severity=severity):
                result = assess_cors([
                    (origin, CorsResponse({
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": str(credentials).lower(),
                        "Access-Control-Allow-Headers": "Authorization",
                    }, body)) for origin in ORIGINS
                ])
                self.assertEqual(result.is_finding, finding)
                self.assertTrue(result.reflected)
                self.assertEqual(result.severity, severity)

    def test_reflection_on_authenticated_responses_is_not_a_finding(self):
        for context in (
            {"request_authenticated": True},
            {"request_cookie": "session=fixture"},
            {"cookie_authenticated": True},
        ):
            with self.subTest(context=context):
                result = assess_cors([
                    (origin, CorsResponse({
                        "Access-Control-Allow-Origin": origin,
                        "Access-Control-Allow-Credentials": "true",
                    }, PRIVATE, **context)) for origin in ORIGINS
                ])
                self.assertFalse(result.is_finding)
                self.assertEqual(result.severity, "INFO")

    def test_reflection_requires_both_probes_to_access_sensitive_data_anonymously(self):
        for second in (
            CorsResponse({"Access-Control-Allow-Origin": ORIGINS[1]}, PRIVATE, 403),
            CorsResponse({"Access-Control-Allow-Origin": ORIGINS[1]}, PRIVATE, request_authenticated=True),
            CorsResponse({"Access-Control-Allow-Origin": ORIGINS[1]}, PUBLIC),
        ):
            result = assess_cors([
                (ORIGINS[0], CorsResponse({"Access-Control-Allow-Origin": ORIGINS[0]}, PRIVATE)),
                (ORIGINS[1], second),
            ])
            self.assertFalse(result.is_finding)

    def test_protected_reflection_is_not_a_finding(self):
        for status in (401, 403):
            result = assess_cors([
                (origin, CorsResponse({
                    "Access-Control-Allow-Origin": origin,
                    "Access-Control-Allow-Credentials": "true",
                    "WWW-Authenticate": 'Basic realm="Stripe"',
                }, b'{"error":{"message":"You did not provide an API key."}}', status))
                for origin in ORIGINS
            ])
            self.assertFalse(result.is_finding)
            self.assertIn("Authentication required", result.summary)

    def test_requests_records_sent_authorization_and_query_keys(self):
        for url, auth_headers in (
            ("https://fixture.invalid", {"Authorization": "Bearer fixture"}),
            ("https://fixture.invalid", {"x-api-key": "fixture"}),
            ("https://fixture.invalid?api_key=fixture", {}),
        ):
            with self.subTest(url=url, header_names=list(auth_headers)):
                session = Mock()
                def respond(method, target, **kwargs):
                    response = FakeResponse({"Access-Control-Allow-Origin": kwargs["headers"]["Origin"]}, PRIVATE)
                    response.request.headers = auth_headers
                    return response
                session.request.side_effect = respond
                result = probe_cors_requests(url, session=session)
                self.assertFalse(result.is_finding)
                self.assertEqual(session.request.call_count, 1)
                self.assertNotIn("Bearer fixture", result.details)

    def test_requests_401_and_403_skip_reflection_confirmation(self):
        for status in (401, 403):
            with self.subTest(status=status):
                session = Mock()
                session.request.side_effect = lambda method, url, **kwargs: FakeResponse({
                    "Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
                    "Access-Control-Allow-Credentials": "true",
                }, PRIVATE, status)
                result = probe_cors_requests("https://fixture.invalid", session=session)
                self.assertFalse(result.is_finding)
                self.assertEqual(session.request.call_count, 1)

    def test_urllib_http_auth_errors_are_protected(self):
        for status in (401, 403):
            with self.subTest(status=status):
                def deny(request, **kwargs):
                    raise HTTPError(request.full_url, status, "Protected", {
                        "Access-Control-Allow-Origin": request.get_header("Origin"),
                        "Access-Control-Allow-Credentials": "true",
                    }, io.BytesIO(PRIVATE))
                opener = Mock(side_effect=deny)
                result = probe_cors_urllib("https://fixture.invalid", opener=opener)
                self.assertFalse(result.is_finding)
                self.assertEqual(opener.call_count, 1)

    def test_reflection_confirmation_does_not_inherit_a_new_cookie(self):
        session = Mock()
        sent_cookies = []
        def respond(method, url, **kwargs):
            sent_cookies.append(kwargs["headers"].get("Cookie"))
            response = FakeResponse({
                "Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
                "Set-Cookie": "session=fixture",
            }, PRIVATE)
            response.request.headers = kwargs["headers"]
            return response
        session.request.side_effect = respond
        result = probe_cors_requests("https://fixture.invalid", session=session)
        self.assertTrue(result.is_finding)
        self.assertEqual(sent_cookies, [None, ""])

    def test_only_reflected_responses_trigger_second_probe(self):
        seen = []
        def reflect(origin):
            seen.append(origin)
            return CorsResponse({"Access-Control-Allow-Origin": origin}, PRIVATE)
        self.assertTrue(probe_cors(reflect).reflected)
        self.assertEqual(len(set(seen)), 2)
        seen.clear()
        def wildcard(origin):
            seen.append(origin)
            return CorsResponse({"Access-Control-Allow-Origin": "*"}, PUBLIC)
        self.assertFalse(probe_cors(wildcard).is_finding)
        self.assertEqual(len(seen), 1)

    def test_requests_and_urllib_adapters_share_policy(self):
        session = Mock()
        session.request.return_value = FakeResponse({"Access-Control-Allow-Origin": "*"})
        self.assertFalse(probe_cors_requests("https://fixture.invalid", session=session).is_finding)
        self.assertFalse(probe_cors_urllib(
            "https://fixture.invalid", opener=lambda *args, **kwargs: FakeResponse({"Access-Control-Allow-Origin": "*"})
        ).is_finding)

    def test_dashboard_scanner_suppresses_public_wildcards_on_all_endpoints(self):
        scanner = MCPScanner("https://fixture.invalid")
        scanner.session.request = Mock(return_value=FakeResponse({"Access-Control-Allow-Origin": "*"}))
        scanner._check_cors()
        self.assertEqual(len(scanner.checks), 4)
        self.assertTrue(all(check.passed and check.risk_level == RiskLevel.INFO for check in scanner.checks))

    def test_dashboard_scanner_reports_sensitive_credentialed_reflection(self):
        scanner = MCPScanner("https://fixture.invalid")
        scanner.session.request = Mock(side_effect=lambda method, url, **kwargs: FakeResponse({
            "Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
            "Access-Control-Allow-Credentials": "true",
        }, PRIVATE))
        scanner._check_cors()
        self.assertTrue(all(not check.passed and check.risk_level == RiskLevel.HIGH for check in scanner.checks))

    def test_dashboard_scanner_suppresses_protected_reflection(self):
        for status in (401, 403):
            scanner = MCPScanner("https://fixture.invalid")
            scanner.session.request = Mock(side_effect=lambda method, url, **kwargs: FakeResponse({
                "Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
                "Access-Control-Allow-Credentials": "true",
            }, PRIVATE, status))
            scanner._check_cors()
            self.assertEqual(len(scanner.checks), 4)
            self.assertTrue(all(check.passed and check.risk_level == RiskLevel.INFO for check in scanner.checks))

    def test_live_cli_suppresses_public_cors_and_reports_sensitive_context(self):
        path = Path(__file__).resolve().parents[1] / "mcp_authscan.py"
        spec = importlib.util.spec_from_file_location("live_cli_cors_test", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for body, credentials, expected, status in (
            (PUBLIC, False, False, 200), (PRIVATE, True, True, 200),
            (PRIVATE, True, False, 401), (PRIVATE, True, False, 403),
        ):
            with self.subTest(expected=expected), patch.object(module.socket, "create_connection"), \
                    patch.object(module, "urlopen", side_effect=lambda *args, **kwargs: FakeResponse({
                        "Access-Control-Allow-Origin": "*",
                        "Access-Control-Allow-Credentials": str(credentials).lower(),
                    }, body, status)), patch("sys.stderr", io.StringIO()):
                findings = [f for f in module.scan_live_server("http://fixture.invalid") if f["rule"] == "D2"]
                self.assertEqual(bool(findings), expected)
                self.assertTrue(all(f["severity"] == "MEDIUM" for f in findings))


if __name__ == "__main__":
    unittest.main()
