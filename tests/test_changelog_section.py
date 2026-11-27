import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from changelog_section import section  # noqa: E402

SAMPLE = """# Changelog

## [Unreleased]

## [1.2.10] - 2026-01-02

### Added
- ten

## [1.2.1] - 2026-01-01

### Fixed
- one

## [1.2.0] - 2026-01-01
"""


def test_extracts_body_until_next_heading():
    assert section(SAMPLE, "1.2.1") == "### Fixed\n- one\n"


def test_version_match_is_exact_not_prefix():
    assert section(SAMPLE, "1.2.10") == "### Added\n- ten\n"
    assert "ten" not in section(SAMPLE, "1.2.1")


@pytest.mark.parametrize("version", ["9.9.9", "1.2.0"])
def test_missing_or_empty_section_raises(version):
    with pytest.raises(LookupError):
        section(SAMPLE, version)


def test_real_changelog_1_1_47_carries_hashes_and_limitations():
    body = section((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), "1.1.47")
    assert "7944a31953f3d12847eb2f08262077f39ce71b8387ce2d9381cd407359c3ff88" in body
    assert "### Security and evidence limitations" in body
    assert not body.startswith("## ")


def test_cli_exits_nonzero_with_no_stdout_for_unknown_version(tmp_path):
    p = tmp_path / "CHANGELOG.md"
    p.write_text(SAMPLE, encoding="utf-8")
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "changelog_section.py"), "9.9.9", str(p)],
        capture_output=True, text=True,
    )
    assert r.returncode == 1 and r.stdout == "" and "no CHANGELOG section" in r.stderr
