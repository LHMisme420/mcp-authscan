"""site_sample regenerates from the installed package; pricing strings audit against pricing.json."""
import json
import re
import subprocess
import sys
from pathlib import Path

from mcp_authscan import site_sample

ROOT = Path(__file__).resolve().parents[1]


def test_site_fixture_is_the_packaged_fixture():
    site = (ROOT / "client" / "src" / "SampleReport.tsx").read_text(encoding="utf-8")
    assert re.search(r"const FIXTURE = `(.*?)`;", site, re.S).group(1) == site_sample.FIXTURE


def test_sample_regenerates_from_installed_version(monkeypatch):
    from importlib.metadata import version
    monkeypatch.setattr(site_sample, "_wheel_sha", lambda v: "0" * 64)
    r = site_sample.run(19192)
    assert r["version"] == version("mcp-authscan")
    assert r["exit_code"] == 1 and r["findings"] == ["HIGH ZERO-AUTH Unauthenticated MCP endpoint"]
    assert re.fullmatch(r"[0-9a-f]{64}", r["report_hash"]) and r["report_verify"].startswith("MATCH")
    new = site_sample.new_strings(r)
    assert new["install"] == 'v/bin/pip install "mcp-authscan[signing]==%s"' % r["version"]


def test_pricing_audit_flags_the_retest_conflict_and_prices_agree():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "pricing_strings.py")], capture_output=True, text=True)
    assert "PRICE NOT IN pricing.json" not in r.stdout
    assert "client/src/PricingTiers.tsx:8  retest INCLUDED with the single server" in r.stdout
    assert "README.md:138  retest attached to the full tier" in r.stdout
    assert "CONFLICT" in r.stdout and r.returncode == 1  # stays red until the Stripe line item is confirmed
    src = json.loads((ROOT / "pricing" / "pricing.json").read_text())
    assert src["tiers"]["single"]["includes_retest"] is None
