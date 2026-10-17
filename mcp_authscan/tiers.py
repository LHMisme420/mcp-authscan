"""History and scan accounting without subscription restrictions."""
import sqlite3
from datetime import datetime, timezone

from flask_jwt_extended import get_jwt


def utc_now():
    return datetime.now(timezone.utc)


def history_connection(db_file, org_id):
    conn = sqlite3.connect(db_file)
    conn.execute('CREATE TEMP VIEW visible_findings AS SELECT * FROM findings')
    return conn


def reserve_scan(db_file, org_id):
    claims = get_jwt()
    if claims.get('bridge'):
        # Only the authenticated gateway can authorize a scan. Payment is not
        # part of that authorization; tenant ownership is checked separately.
        return bool(claims.get('scan_authorized'))
    month = utc_now().strftime('%Y-%m')
    with sqlite3.connect(db_file, timeout=15) as conn:
        conn.execute('BEGIN IMMEDIATE')
        changed = conn.execute(
            '''UPDATE organizations
               SET monthly_scan_count=CASE WHEN scan_count_month=? THEN coalesce(monthly_scan_count,0)+1 ELSE 1 END,
                   scan_count_month=?
               WHERE id=?''',
            (month, month, org_id),
        ).rowcount
    return changed == 1
