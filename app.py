
@app.route('/api/threat-intelligence', methods=['GET'])
@jwt_required()
def threat_intelligence():
    """Get threat intelligence and trends"""
    org_id = int(get_jwt_identity())
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Get recent findings
        c.execute('SELECT severity FROM findings WHERE org_id = ? ORDER BY created_at DESC LIMIT 100', (org_id,))
        recent = [row[0] for row in c.fetchall()]
        
        # Calculate trend
        c.execute('''SELECT COUNT(*) FROM findings WHERE org_id = ? AND created_at > datetime('now', '-7 days')''', (org_id,))
        week_count = c.fetchone()[0]
        
        c.execute('''SELECT COUNT(*) FROM findings WHERE org_id = ? AND created_at > datetime('now', '-30 days')''', (org_id,))
        month_count = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_findings': len(recent),
            'critical': recent.count('CRITICAL'),
            'high': recent.count('HIGH'),
            'medium': recent.count('MEDIUM'),
            'week_trend': week_count,
            'month_trend': month_count,
            'trend_direction': 'increasing' if week_count > month_count/4 else 'decreasing'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
