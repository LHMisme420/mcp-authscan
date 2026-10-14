#!/usr/bin/env python3
import sqlite3
from datetime import datetime, timedelta

class ThreatIntelligence:
    def __init__(self):
        self.conn = sqlite3.connect('vata.db')
        self.c = self.conn.cursor()
    
    def calculate_threat_score(self, findings):
        """Calculate overall threat score 0-100"""
        if not findings:
            return 0
        
        critical = len([f for f in findings if f['severity'] == 'CRITICAL'])
        high = len([f for f in findings if f['severity'] == 'HIGH'])
        medium = len([f for f in findings if f['severity'] == 'MEDIUM'])
        
        # CRITICAL=40 points, HIGH=20 points, MEDIUM=10 points
        score = 100 - (critical*40 + high*20 + medium*10)
        return max(0, score)
    
    def get_trend(self, org_id, days=30):
        """Get vulnerability trend over time"""
        self.c.execute('''
            SELECT DATE(created_at) as date, COUNT(*) as count
            FROM findings
            WHERE org_id = ? AND created_at > datetime('now', '-' || ? || ' days')
            GROUP BY DATE(created_at)
            ORDER BY date DESC
        ''', (org_id, days))
        return self.c.fetchall()
    
    def identify_patterns(self, org_id):
        """Find patterns in vulnerabilities"""
        self.c.execute('''
            SELECT vector_type, COUNT(*) as count, severity
            FROM findings
            WHERE org_id = ?
            GROUP BY vector_type, severity
            ORDER BY count DESC
        ''', (org_id,))
        return self.c.fetchall()

if __name__ == "__main__":
    ti = ThreatIntelligence()
    print("✅ Threat intelligence module loaded")
