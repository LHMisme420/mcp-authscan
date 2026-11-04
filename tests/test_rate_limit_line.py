import types
from mcp_authscan.report_copy import rate_limit_line

def _r(s, d, l):
    return types.SimpleNamespace(status=s, detail=d, limitation=l)

def test_excluded():
    assert rate_limit_line(_r("EXCLUDED", "", "no budget supplied")) == "Rate limiting (excluded): no budget supplied"

def test_not_observed():
    assert rate_limit_line(_r("NOT_OBSERVED", "no 429 in budget", "")) == "Rate limiting (not_observed): no 429 in budget"

def test_pass():
    assert rate_limit_line(_r("PASS", "429 after 3 requests", "")) == "Rate limiting (pass): 429 after 3 requests"

def test_detail_wins():
    assert rate_limit_line(_r("FAIL", "429 only after 40", "budget 4")) == "Rate limiting (fail): 429 only after 40"

def test_no_record():
    assert rate_limit_line(None) == "Rate limiting: no record was produced for this scan"
