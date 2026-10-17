"""Shared SQLite schema; importing this module needs only the Python stdlib."""
import sqlite3


def initialize_database(db_file):
    """Create or extend the findings schema without replacing existing records."""
    with sqlite3.connect(db_file) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY, name TEXT UNIQUE, api_key TEXT UNIQUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(organizations)')}
        for name, definition in (
            ('owner_user_id', 'TEXT'),
            ('subscription_tier', "TEXT NOT NULL DEFAULT 'free'"),
            ('monthly_scan_count', 'INTEGER NOT NULL DEFAULT 0'),
            ('scan_count_month', 'TEXT'),
            ('subscription_expires_at', 'TEXT'),
        ):
            if name not in columns:
                conn.execute(f'ALTER TABLE organizations ADD COLUMN {name} {definition}')
        conn.execute('''CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY, org_id INTEGER, vector_type TEXT, severity TEXT,
            description TEXT, remediation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        columns = {row[1] for row in conn.execute('PRAGMA table_info(findings)')}
        for name, definition in (('server_name', 'TEXT'), ('rule', 'TEXT'), ('scan_id', 'INTEGER')):
            if name not in columns:
                conn.execute(f'ALTER TABLE findings ADD COLUMN {name} {definition}')
        conn.execute('''CREATE TABLE IF NOT EXISTS compliance_reports (
            id INTEGER PRIMARY KEY, org_id INTEGER, score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS scan_runs (
            id INTEGER PRIMARY KEY, org_id INTEGER NOT NULL, target TEXT NOT NULL,
            status TEXT NOT NULL, total_checks INTEGER NOT NULL DEFAULT 0,
            findings_count INTEGER NOT NULL DEFAULT 0, critical_count INTEGER NOT NULL DEFAULT 0,
            high_count INTEGER NOT NULL DEFAULT 0, compliance_score INTEGER, error TEXT,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, completed_at TIMESTAMP)''')
        # Audit trail: each row records a user's attestation that they are
        # authorized to scan a given target (see the /api/scans/mcp gate).
        conn.execute('''CREATE TABLE IF NOT EXISTS scan_authorizations (
            id INTEGER PRIMARY KEY, org_id TEXT, target TEXT,
            attested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
