from mcp_authscan.tools_digest_footer import footer_line


def test_captured_names_digest_count_and_scope():
    line = footer_line({"tools_digest": {"captured": True, "tool_count": 2, "digest": "abc123"}})
    assert "abc123" in line
    assert "2 tools" in line
    assert "Outside the hash" in line
    assert "not a verdict" in line


def test_not_captured_gives_the_reason_and_claims_nothing():
    line = footer_line({"tools_digest": {"captured": False, "reason": "initialize returned HTTP 401"}})
    assert "initialize returned HTTP 401" in line
    assert "No effect on verdicts or coverage" in line


def test_missing_section_is_stated_not_faked():
    assert "not recorded" in footer_line({})
