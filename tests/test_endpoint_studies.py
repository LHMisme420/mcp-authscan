"""Endpoint-study counts never appear without their study id; 16585 never appears at all."""
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("endpoint_studies", ROOT / "tools" / "endpoint_studies.py")
es = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es)


def test_readme_block_is_generated_from_the_registry():
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "endpoint_studies.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_no_recorded_count_without_its_study_id_in_the_same_paragraph():
    assert es.violations(es.published_texts()) == []


def test_the_check_catches_a_bare_count():
    texts = {"x": "Intro.\n\nWe walked 16,072 registry endpoints.\n\nMore.",
             "y": "Of those, 14339 speak MCP and 57.1% answered.",
             "ok": "Study EP-2ddd960 (2026-11-07): 16,072 walked."}
    got = {(w, f) for w, f, _ in es.violations(texts)}
    assert got == {("x", "16,072"), ("y", "14339"), ("y", "57.1%")}


def test_16585_appears_in_nothing_a_buyer_can_read():
    assert es.forbidden(es.published_texts()) == []
    assert es.forbidden({"x": "about 16,585 servers"}) == [("x", "16,585")]


def test_every_unsourced_field_is_empty_not_estimated():
    for s in es.REG["studies"]:
        if not s["registry_walk"]:
            assert s["walk_finished"] == "", s["id"]
        if s["endpoints"] is None:
            assert s["speak_mcp"] is None and s["figures"] == {}, s["id"]
