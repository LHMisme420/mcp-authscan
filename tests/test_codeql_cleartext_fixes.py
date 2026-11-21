"""Regression tests for the CodeQL clear-text alerts fixed on fix/codeql-cleartext-alerts.

#209/#207 tools/scope_check.py: the printed/serialized token exchange is built from an
allowlist; the client secret, live tokens, an echoed secret and cookies never reach it.
#211 mcp_authscan/monolith.py: discovery_status in the report is one of a closed set of
constants, never a value read from the discovery result.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import scope_check as sc  # noqa: E402

from mcp_authscan.monolith import DISCOVERY_STATUSES, discovery_status_of  # noqa: E402

SECRET = "s3cr3t-client-secret-value"
LIVE_ACCESS = "liveopaqueaccesstoken0123456789"
LIVE_REFRESH = "liverefreshtoken9876543210abcdef"


def _record(body_text: str | None = None, extra_headers: dict | None = None) -> dict:
    body_json = {"access_token": LIVE_ACCESS, "refresh_token": LIVE_REFRESH,
                 "token_type": "Bearer", "scope": "read"}
    return {
        "request": {
            "method": "POST",
            "url": "https://as.example/token",
            "headers": {"Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json"},
            "body": {"grant_type": "client_credentials", "client_id": "cid",
                     "client_secret": SECRET, "scope": "read"},
        },
        "response": {
            "status": 200,
            "headers": {"Content-Type": "application/json", "Set-Cookie": "sid=abc123",
                        **(extra_headers or {})},
            "body_text": json.dumps(body_json) if body_text is None else body_text,
            "body_json": body_json,
        },
        "access_token": LIVE_ACCESS,
        "error": None,
    }


def test_display_never_contains_secret_or_live_tokens():
    out = json.dumps(sc.redact_exchange_for_display(_record()))
    for raw in (SECRET, LIVE_ACCESS, LIVE_REFRESH, "sid=abc123"):
        assert raw not in out, raw
    shown = sc.redact_exchange_for_display(_record())
    assert shown["request"]["body"]["client_secret"] == "<redacted>"
    assert shown["access_token"] == LIVE_ACCESS[:8] + "…<redacted>"
    assert shown["response"]["body_json"]["refresh_token"] == LIVE_REFRESH[:8] + "…<redacted>"
    assert shown["response"]["headers"]["Set-Cookie"] == "<redacted>"
    assert shown["response"]["body_json"]["scope"] == "read"


def test_raw_body_text_is_scrubbed():
    # Before this fix body_text was printed verbatim, carrying the live token.
    shown = sc.redact_exchange_for_display(_record())
    assert LIVE_ACCESS not in shown["response"]["body_text"]
    assert LIVE_ACCESS[:8] + "…<redacted>" in shown["response"]["body_text"]


def test_secret_echoed_by_server_is_scrubbed():
    rec = _record(body_text='{"error":"invalid_client","error_description":"bad secret ' + SECRET + '"}')
    rec["response"]["body_json"] = {"error": "invalid_client",
                                    "error_description": "bad secret " + SECRET}
    out = json.dumps(sc.redact_exchange_for_display(rec))
    assert SECRET not in out


def test_fixture_and_jwt_tokens_stay_visible():
    rec = _record()
    jwt = "eyJhbGciOiJub25lIn0.eyJzY29wZSI6InJlYWQifQ."
    rec["access_token"] = jwt
    rec["response"]["body_json"] = {"access_token": jwt, "refresh_token": "fixture-refresh"}
    rec["response"]["body_text"] = json.dumps(rec["response"]["body_json"])
    shown = sc.redact_exchange_for_display(rec)
    assert shown["access_token"] == jwt
    assert shown["response"]["body_json"] == {"access_token": jwt, "refresh_token": "fixture-refresh"}


def test_redaction_is_idempotent():
    once = sc.redact_exchange_for_display(_record())
    assert sc.redact_exchange_for_display(once) == once


def test_discovery_status_closed_set():
    for status in DISCOVERY_STATUSES:
        assert discovery_status_of({"status": status}) == status
    assert discovery_status_of(None) is None
    assert discovery_status_of({}) is None
    assert discovery_status_of({"status": "hunter2"}) is None


def test_every_status_literal_in_monolith_is_in_the_closed_set():
    # A new discovery status added without updating DISCOVERY_STATUSES would be
    # silently reported as null; fail here instead.
    import re
    src = (ROOT / "mcp_authscan" / "monolith.py").read_text(encoding="utf-8")
    written = set(re.findall(r'"status":\s*"([A-Z_]+)"', src))
    assert written <= set(DISCOVERY_STATUSES), written - set(DISCOVERY_STATUSES)


def test_non_dict_record_yields_empty_display():
    assert sc.redact_exchange_for_display(None) == {}
