#!/usr/bin/env python3
"""Property-based tests (hypothesis) for the security-critical detection logic,
plus output-contract checks for the JSON and SARIF report shapes.
"""
import json
import unittest

from hypothesis import given
from hypothesis import strategies as st

from mcp_authscan.cli import load_targets, parse_headers
from mcp_authscan.cors import PROFILE_FIELDS, SECRET_FIELDS, sensitive_user_data
from mcp_authscan.report import SecurityReport, build_sarif
from mcp_authscan.scanner import Check, RiskLevel

# Keys that must not appear in "benign" generated data (they carry meaning to
# the detector). Normalization in cors.py lowercases and splits camelCase, so
# compare against a lowercased reserved set.
_RESERVED = {k.lower() for k in SECRET_FIELDS | PROFILE_FIELDS} | {
    "user", "users", "current_user", "profile", "account", "accounts"}
_safe_keys = st.text(alphabet="abcdefghijklmnopqrstuvwxyz_", min_size=1, max_size=12).filter(
    lambda k: k.lower() not in _RESERVED)
_json_scalars = st.one_of(st.text(max_size=20), st.integers(), st.booleans(), st.none())


class SensitiveDataProperties(unittest.TestCase):
    @given(st.dictionaries(_safe_keys, _json_scalars, max_size=8))
    def test_benign_objects_are_never_flagged(self, obj):
        # No secret/profile keys present -> never "sensitive user data".
        self.assertFalse(sensitive_user_data(json.dumps(obj).encode()))

    @given(st.text(min_size=1, max_size=40).filter(lambda s: s.strip()))
    def test_populated_secret_field_is_always_flagged(self, token):
        self.assertTrue(sensitive_user_data(json.dumps({"access_token": token}).encode()))

    @given(st.sampled_from(sorted(SECRET_FIELDS)))
    def test_empty_secret_field_is_not_flagged(self, field):
        # An empty value is not evidence of exposed data.
        self.assertFalse(sensitive_user_data(json.dumps({field: ""}).encode()))

    @given(st.text(max_size=50))
    def test_arbitrary_non_json_is_never_sensitive(self, blob):
        # Non-JSON / free text is inconclusive, never a finding.
        try:
            json.loads(blob)
        except ValueError:
            self.assertFalse(sensitive_user_data(blob.encode()))


class CliHelperProperties(unittest.TestCase):
    @given(st.lists(st.text(alphabet="abcdef", min_size=1, max_size=5), max_size=10))
    def test_load_targets_dedupes_and_preserves_order(self, urls):
        out = load_targets(urls, None)
        self.assertEqual(out, list(dict.fromkeys(urls)))   # first-seen order, no dups

    @given(st.text(min_size=1, max_size=10).filter(lambda s: ":" not in s))
    def test_parse_headers_rejects_missing_colon(self, bad):
        with self.assertRaises(ValueError):
            parse_headers([bad])

    @given(
        st.text(alphabet="ABCDEFghij-", min_size=1, max_size=10),
        st.text(alphabet="xyz123 ", max_size=10),
    )
    def test_parse_headers_roundtrips_name_value(self, name, value):
        parsed = parse_headers([f"{name}: {value}"])
        self.assertEqual(parsed[name], value.strip())


class OutputContractTests(unittest.TestCase):
    def _checks(self):
        return [Check("n", "d", "/e", "GET", RiskLevel.CRITICAL, False, "det", "rem"),
                Check("n2", "d", "/e2", "GET", RiskLevel.INFO, True, "det", "rem")]

    def test_json_report_contract(self):
        data = SecurityReport(self._checks(), "http://t").to_dict()
        self.assertEqual(set(data), {"summary", "checks"})
        for key in ("target", "total_checks", "passed", "failed", "critical", "high"):
            self.assertIn(key, data["summary"])
        for c in data["checks"]:
            self.assertEqual(set(c), {"name", "endpoint", "risk_level", "passed",
                                      "details", "remediation"})

    def test_sarif_contract(self):
        doc = build_sarif([("http://t", self._checks())], "1.0.0")
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertIn("tool", run)
        self.assertEqual(len(run["results"]), 1)   # only the failed check
        r = run["results"][0]
        for key in ("ruleId", "level", "message", "locations"):
            self.assertIn(key, r)


if __name__ == "__main__":
    unittest.main()
