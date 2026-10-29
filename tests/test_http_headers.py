"""Headers must look names up case-insensitively, whatever case they arrived in."""
from mcp_authscan.http_headers import Headers


def test_get_finds_header_that_arrived_as_cache_control():
    h = Headers({'Cache-Control': 'no-store'})
    assert h.get('Cache-Control') == 'no-store'
    assert h.get('cache-control') == 'no-store'


def test_getitem_and_contains_are_case_insensitive():
    h = Headers({'Cache-Control': 'no-store'})
    assert h['CACHE-CONTROL'] == 'no-store'
    assert 'cache-control' in h
