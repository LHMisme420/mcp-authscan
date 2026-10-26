"""Fixture test: failed scan with zero findings should not be scored.

Proves that compliance_score is None when:
- One or more scan rows exist
- But none have status='completed'
- And there are zero findings

This guards against unearned 100% scores from crashed/failed scans.
"""
import json
import sqlite3
from pathlib import Path
from io import BytesIO
from contextlib import closing

import pytest
from pdfminer.high_level import extract_text


def test_failed_scan_zero_findings_json_report_not_scored(app, test_client, org_id):
    """JSON compliance report shows None score when only failed scans exist."""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Insert one failed scan with zero findings
        conn.execute(
            'INSERT INTO scan_runs (org_id, target, status, error) VALUES (?,?,?,?)',
            (org_id, 'https://failed.example.com', 'failed', 'Connection timeout')
        )

    # Get JSON report
    response = test_client.get('/api/reports/compliance')
    assert response.status_code == 200
    data = response.get_json()

    # Should not have unearned 100%
    assert data['compliance_score'] is None, "Failed scan should not produce a score"
    assert data['total_findings'] == 0


def test_failed_scan_zero_findings_pdf_report_shows_not_assessed(app, test_client, org_id):
    """PDF report shows 'Not assessed' when only failed scans exist."""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Insert one failed scan with zero findings
        conn.execute(
            'INSERT INTO scan_runs (org_id, target, status, error) VALUES (?,?,?,?)',
            (org_id, 'https://failed.example.com', 'failed', 'Connection timeout')
        )

    # Get PDF report
    response = test_client.get('/api/reports/pdf')
    assert response.status_code == 200
    assert response.content_type == 'application/pdf'

    # Extract text from PDF
    pdf_text = extract_text(BytesIO(response.data))

    # Should show "Not assessed", not a percentage
    assert 'Not assessed' in pdf_text, "PDF should show 'Not assessed' for failed scan"
    assert '%' not in pdf_text or 'Not assessed' in pdf_text.split('%')[0], \
        "PDF should not show compliance percentage"


def test_running_scan_zero_findings_not_scored(app, test_client, org_id):
    """Running scan (incomplete) should also not be scored."""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Insert one running scan with zero findings
        conn.execute(
            'INSERT INTO scan_runs (org_id, target, status) VALUES (?,?,?)',
            (org_id, 'https://running.example.com', 'running')
        )

    # Get JSON report
    response = test_client.get('/api/reports/compliance')
    assert response.status_code == 200
    data = response.get_json()

    # Should not score running scans
    assert data['compliance_score'] is None, "Running scan should not produce a score"


def test_completed_scan_zero_findings_gets_100_percent(app, test_client, org_id):
    """Completed scan with zero findings should get 100%."""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Insert one completed scan with zero findings
        conn.execute(
            'INSERT INTO scan_runs (org_id, target, status, total_checks, findings_count, completed_at) '
            'VALUES (?,?,?,?,?, CURRENT_TIMESTAMP)',
            (org_id, 'https://clean.example.com', 'completed', 9, 0)
        )

    # Get JSON report
    response = test_client.get('/api/reports/compliance')
    assert response.status_code == 200
    data = response.get_json()

    # Should score completed scans
    assert data['compliance_score'] == 100, "Completed scan with no findings = 100%"


def test_mixed_failed_and_completed_uses_completed_score(app, test_client, org_id):
    """When there's both failed and completed scans, use only the completed score."""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Insert one failed scan
        conn.execute(
            'INSERT INTO scan_runs (org_id, target, status, error) VALUES (?,?,?,?)',
            (org_id, 'https://failed.example.com', 'failed', 'Timeout')
        )
        # Insert one completed scan with zero findings
        conn.execute(
            'INSERT INTO scan_runs (org_id, target, status, total_checks, findings_count, completed_at) '
            'VALUES (?,?,?,?,?, CURRENT_TIMESTAMP)',
            (org_id, 'https://clean.example.com', 'completed', 9, 0)
        )

    # Get JSON report
    response = test_client.get('/api/reports/compliance')
    assert response.status_code == 200
    data = response.get_json()

    # Should use the completed scan's score (100%), not fail due to the failed scan
    assert data['compliance_score'] == 100, "Should score based on completed scans only"
