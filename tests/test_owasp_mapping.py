import re

from mcp_authscan import owasp_mapping as m


def test_every_mapped_category_exists():
    for rule, cid in m.RULE_CATEGORY.items():
        assert cid in m.CATEGORIES, "%s maps to unknown category %s" % (rule, cid)


def test_all_eleven_authserver_probes_are_mapped():
    for n in range(1, 12):
        assert "OAuth-%d" % n in m.RULE_CATEGORY


def test_untested_categories_name_a_reason():
    for cid in ("MCP03", "MCP04", "MCP05", "MCP06", "MCP08", "MCP09", "MCP10"):
        assert cid in m.UNTESTED, cid
        assert m.UNTESTED[cid].strip()


def test_mapping_version_is_dated():
    assert re.fullmatch(r"\d{4}\.\d{2}\.\d{2}\.\d+", m.MAPPING_VERSION)


def test_tag_reads_as_category_and_name():
    assert m.tag("OAuth-4") == "MCP01 Token Mismanagement & Secret Exposure"
    assert m.tag("nope") == "unmapped"
    assert m.tag(None) == "unmapped"


def test_coverage_rows_account_for_all_ten():
    rows = m.coverage_rows()
    assert len(rows) == 10
    assert {r[0] for r in rows} == set(m.CATEGORIES)


def test_partial_is_not_counted_as_covered_or_untested():
    assert "MCP02" in m.PARTIAL
    assert "MCP02" not in m.UNTESTED


def test_sarif_rules_tags_mapped_rules_only():
    from mcp_authscan.owasp_mapping import sarif_rules
    given = [{"id": "OAuth-6"}, {"id": "A1"}, {"id": "OAuth-9", "properties": {"k": 1}}]
    out = sarif_rules(given)
    assert out[0]["properties"]["owasp"].startswith("MCP07")
    assert "owasp" not in (out[1].get("properties") or {})
    assert out[2]["properties"]["k"] == 1
    assert out[2]["properties"]["owasp"].startswith("MCP07")
    assert out[2]["properties"]["owaspMapping"]
    assert "properties" not in given[0]


def test_coverage_page_matches_generator():
    import pathlib, sys
    sys.path.insert(0, "tools")
    import render_coverage
    page = pathlib.Path("docs/owasp-coverage.md").read_text()
    assert page == render_coverage.render(), "docs page is stale, rerun tools/render_coverage.py"
