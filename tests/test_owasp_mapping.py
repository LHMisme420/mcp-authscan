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
    given = [{"id": "OAuth-6"}, {"id": "A4"}, {"id": "OAuth-9", "properties": {"k": 1}}]
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


def _emitted_rules():
    """Every rule id the package can emit, discovered from source so a new rule cannot slip in unmapped."""
    import ast, glob, re
    from pathlib import Path
    pkg = Path(__file__).resolve().parents[1] / "mcp_authscan"
    pat = re.compile(r"^(OAuth-\d+|[A-E]\d+|ZERO-AUTH|MCP[A-Z]*-[A-Z]*-?\d+|MCP[A-Z]-\d+|DESC-T\d|cors|potential_unauthenticated_sensitive_data)$")
    found = {"OAuth-%d" % i for i in range(1, 12)}
    for f in glob.glob(str(pkg / "*.py")):
        tree = ast.parse(Path(f).read_text(encoding="utf-8"))
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) == "add" and len(n.args) >= 2 \
                    and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
                found.add(n.args[1].value)
            if isinstance(n, ast.Assign) and any(getattr(t, "id", "") in ("RULE", "DRIFT_RULE") for t in n.targets) \
                    and isinstance(n.value, ast.Constant):
                found.add(n.value.value)
            if isinstance(n, ast.Dict):
                for k, v in zip(n.keys, n.values):
                    if isinstance(k, ast.Constant) and k.value in ("rule", "test_id") and isinstance(v, ast.Constant) \
                            and isinstance(v.value, str) and pat.match(v.value):
                        found.add(v.value)
    found |= {"DESC-T1", "DESC-T2", "DESC-T3", "DESC-T4"}
    return {r for r in found if pat.match(r)}


def test_every_emitted_rule_is_mapped_or_named_unmapped():
    from mcp_authscan.owasp_mapping import NO_CATEGORY, RULE_CATEGORY
    emitted = _emitted_rules()
    assert {"A1", "E3", "MCP-TRANSPORT-1", "MCPD-1", "ZERO-AUTH", "DESC-T4"} <= emitted  # discovery works
    missing = sorted(r for r in emitted if r not in RULE_CATEGORY and r not in NO_CATEGORY)
    assert not missing, "rules with no OWASP decision: %s" % missing
    for r, why in NO_CATEGORY.items():
        assert r not in RULE_CATEGORY and len(why) > 40


def test_description_rows_and_findings_carry_owasp_in_json_and_sarif():
    import json, subprocess, sys
    from tests.test_exit_code_fixtures import ROOT, fixture
    auth = ["--authorized-by", "x", "--auth-basis", "y", "--contact", "z@example.test", "--allow-private"]
    with fixture("description_fixture_flagged.py", 9412):
        j = subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), "http://127.0.0.1:9412/mcp", *auth, "--json"],
                           cwd=ROOT, capture_output=True, text=True, timeout=90)
        s = subprocess.run([sys.executable, str(ROOT / "mcp_authscan.py"), "http://127.0.0.1:9412/mcp", *auth, "--sarif"],
                           cwd=ROOT, capture_output=True, text=True, timeout=90)
    rep = json.loads(j.stdout[j.stdout.find("{"):])
    assert all(f.get("owasp") and f["owasp"] != "unmapped" for f in rep["findings"])
    flagged = [p for p in rep["probes"] if p.get("probe_class") == "description" and p["status"] == "FLAGGED"]
    assert flagged and all(p["owasp"] == "MCP03 Tool Poisoning" for p in flagged)
    sarif = json.loads(s.stdout[s.stdout.find("{"):])
    res = [x for x in sarif["runs"][0]["results"] if x["ruleId"].startswith("DESC-")]
    assert res and all(x["properties"]["owasp"] == "MCP03 Tool Poisoning" for x in res)
    rules = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["DESC-T1"]["properties"]["owasp"] == "MCP03 Tool Poisoning"
