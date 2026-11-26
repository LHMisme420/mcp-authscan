"""Execute real v1.1.46 preflight against controlled HTTP responses."""
import io
from contextlib import redirect_stderr
from unittest.mock import patch
from urllib.error import HTTPError

import pytest
from mcp_authscan import monolith


class StopAfterPreflight(Exception):
    pass


@pytest.mark.parametrize(
    "name,header,should_verify",
    [
        ("NONSENSE_SCHEME", 'Nonsense realm="example"', False),
        ("MISSING_HEADER", None, False),
        ("VALID_BEARER_CONTROL", 'Bearer realm="example"', True),
    ],
)
def test_preflight_challenge(name, header, should_verify):
    headers = {}
    if header is not None:
        headers["WWW-Authenticate"] = header

    def fake_open(request, **kwargs):
        raise HTTPError(
            request.full_url, 401, "Unauthorized",
            headers, io.BytesIO(b""),
        )

    def stop_discovery(*args, **kwargs):
        raise StopAfterPreflight()

    output = io.StringIO()
    try:
        with patch.object(monolith, "pinned_open", side_effect=fake_open), \
             patch.object(monolith, "discover_oauth_endpoints",
                          side_effect=stop_discovery), \
             redirect_stderr(output):
            monolith.scan_live_server("https://fixture.invalid/mcp")
    except StopAfterPreflight:
        pass
    else:
        pytest.fail("Preflight did not reach the discovery boundary")

    log = output.getvalue()
    verified = "[+] MCP server verified (HTTP 401 Bearer challenge)" in log
    rejected = "[!] No MCP surface detected" in log

    passed = (verified and not rejected) if should_verify else (
        rejected and not verified
    )

    print(f"\n{name}: {'HIT' if passed else 'MISS'}")
    if not passed:
        print(log)

    assert passed, f"{name}: unexpected MCP preflight classification"
