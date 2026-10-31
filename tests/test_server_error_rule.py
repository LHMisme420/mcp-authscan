from mcp_authscan._common import record
from mcp_authscan.oauth_probes_v2 import _apply_server_error_rule


def test_5xx_clears_a_pass():
    r = record(probe_id=3, name="token-cache-control", status="PASS", http_status=503,
               evidence="headers", probe_class="authserver")
    _apply_server_error_rule([r])
    assert r.status == "NOT_OBSERVED"
    assert r.severity is None


def test_5xx_clears_a_fail():
    r = record(probe_id=4, name="token-cors", status="FAIL", http_status=500,
               evidence="headers", severity="HIGH", probe_class="authserver",
               endpoint="auth.example.com/token")
    _apply_server_error_rule([r])
    assert r.status == "NOT_OBSERVED"
    assert r.severity is None


def test_2xx_pass_survives():
    r = record(probe_id=3, name="token-cache-control", status="PASS", http_status=200,
               evidence="headers", probe_class="authserver")
    _apply_server_error_rule([r])
    assert r.status == "PASS"
