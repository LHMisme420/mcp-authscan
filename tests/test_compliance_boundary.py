"""Boundary rendering must not change the existing report integrity contract."""
import copy
import hashlib
import json
from unittest.mock import patch

from reportlab.platypus import LongTable

from mcp_authscan.compliance_pdf import (
    _boundary_section,
    canonical_report_content,
    compute_canonical_findings_hash,
    generate_compliance_pdf,
)


def render(boundary=None):
    return generate_compliance_pdf(
        {'id': 1, 'name': 'Synthetic workspace'},
        {'total_findings': 0, 'compliance_score': None},
        {}, [], (), 'a' * 64, boundary,
    )


def test_optional_boundary_preserves_positional_callers_and_hash():
    expected_content = {
        'schema_version': 3, 'hash_scheme': 'pdf-recompute-v1',
        'scan_runs': [], 'severity_counts': {}, 'findings': [],
    }
    expected_hash = hashlib.sha256(json.dumps(
        expected_content, sort_keys=True, separators=(',', ':'),
        ensure_ascii=True, allow_nan=False,
    ).encode('utf-8')).hexdigest()
    assert canonical_report_content([], {}, ()) == expected_content
    assert compute_canonical_findings_hash([], {}, ()) == expected_hash
    assert render().startswith(b'%PDF')
    boundary = {'rows': [{'tool': 'synthetic', 'grade': 'MATCH'}], 'digest': 'b' * 64}
    original = copy.deepcopy(boundary)
    assert render(boundary).startswith(b'%PDF')
    assert boundary == original
    assert compute_canonical_findings_hash([], {}, ()) == expected_hash


def test_boundary_is_inserted_before_findings_and_escapes_untrusted_text():
    captured = []

    def capture(_doc, story, **_kwargs):
        captured.extend(story)

    boundary = {
        'rows': [
            {'tool': '<b>synthetic</b>', 'declared': '<script>x</script>',
             'observed': 'read only', 'grade': ' match '},
            {'tool': 'two', 'grade': 'MISMATCH'},
            {'tool': 'three', 'grade': 'unknown'},
        ],
        'digest': 'c' * 64,
    }
    with patch('mcp_authscan.compliance_pdf.SimpleDocTemplate.build', capture):
        render(boundary)
    text = [item.getPlainText() for item in captured if hasattr(item, 'getPlainText')]
    assert text.index('Declared vs observed') < text.index('Findings by severity')
    headline = next(value for value in text if 'Declaration check,' in value)
    assert '1 MATCH, 1 MISMATCH, 1 UNVERIFIED across 3 tools' in headline
    assert 'not proof that the server enforces anything' in headline
    assert 'no credential and no tool call' in headline
    assert any('Graded-row digest (SHA-256): ' + 'c' * 64 in value for value in text)
    table = next(item for item in captured
                 if isinstance(item, LongTable) and len(item._cellvalues[0]) == 4)
    assert table.repeatRows == 1
    assert table._cellvalues[1][0].getPlainText() == '<b>synthetic</b>'
    assert table._cellvalues[1][1].getPlainText() == '<script>x</script>'
    assert table._cellvalues[3][3].getPlainText() == 'UNVERIFIED'


def test_missing_or_empty_boundary_has_no_section():
    assert _boundary_section(None, {}, 540) == []
    assert _boundary_section({}, {}, 540) == []
    assert _boundary_section({'rows': []}, {}, 540) == []
