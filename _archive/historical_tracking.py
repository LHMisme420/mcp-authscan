#!/usr/bin/env python3
import sqlite3
from datetime import datetime

def create_history_table():
    conn = sqlite3.connect('vata.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY,
        org_id INTEGER,
        scan_date TEXT,
        total_findings INTEGER,
        critical_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        compliance_score INTEGER,
        created_at TIMESTAMP
    )''')
    conn.commit()
    conn.close()
    print("✅ History table created")

def log_scan_result(org_id, findings, compliance_score):
    """Log scan results for historical tracking"""
    conn = sqlite3.connect('vata.db')
    c = conn.cursor()
    
    critical = len([f for f in findings if f.get('severity') == 'CRITICAL'])
    high = len([f for f in findings if f.get('severity') == 'HIGH'])
    medium = len([f for f in findings if f.get('severity') == 'MEDIUM'])
    
    c.execute('''INSERT INTO scan_history 
        (org_id, scan_date, total_findings, critical_count, high_count, medium_count, compliance_score, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (org_id, datetime.now().strftime('%Y-%m-%d'), len(findings), critical, high, medium, compliance_score, datetime.now()))
    
    conn.commit()
    conn.close()
    print(f"✅ Scan logged: {len(findings)} findings, {compliance_score}% compliance")

if __name__ == "__main__":
    create_history_table()
