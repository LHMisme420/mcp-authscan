#!/usr/bin/env python3
import sqlite3
import json
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
CORS(app)

# Configuration
app.config['JWT_SECRET_KEY'] = 'vata-secret-key-change-in-production'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

DB_FILE = 'vata.db'

def init_db():
    """Initialize database with required tables"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE,
        api_key TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY,
        org_id INTEGER,
        vector_type TEXT,
        severity TEXT,
        description TEXT,
        remediation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (org_id) REFERENCES organizations(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS compliance_reports (
        id INTEGER PRIMARY KEY,
        org_id INTEGER,
        score INTEGER,
        report_pdf BLOB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (org_id) REFERENCES organizations(id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY,
        org_id INTEGER,
        scan_date TEXT,
        total_findings INTEGER,
        critical_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        compliance_score INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (org_id) REFERENCES organizations(id)
    )''')
    
    conn.commit()
    conn.close()

# Initialize database
init_db()

# ============ Health & Status ============
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'version': '2.0'}), 200

# ============ Authentication ============
@app.route('/auth/register', methods=['POST'])
def register():
    """Register new organization"""
    try:
        data = request.get_json()
        username = data.get('username', f'user_{datetime.now().timestamp()}')
        org_name = data.get('org_name', username)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Check if org exists
        c.execute('SELECT id FROM organizations WHERE name = ?', (org_name,))
        existing = c.fetchone()
        
        if existing:
            org_id = existing[0]
        else:
            # Create new org
            api_key = f'vata_key_{org_name.replace(" ", "_")}_{int(datetime.now().timestamp())}'
            c.execute('INSERT INTO organizations (name, api_key) VALUES (?, ?)', (org_name, api_key))
            conn.commit()
            org_id = c.lastrowid
        
        # Create JWT token
        access_token = create_access_token(identity=str(org_id))
        
        conn.close()
        return jsonify({'access_token': access_token, 'org_id': org_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    """Login to organization"""
    try:
        data = request.get_json()
        username = data.get('username')
        org_name = data.get('org_name', username)
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute('SELECT id FROM organizations WHERE name = ?', (org_name,))
        result = c.fetchone()
        conn.close()
        
        if not result:
            return jsonify({'error': 'Organization not found'}), 404
        
        org_id = result[0]
        access_token = create_access_token(identity=str(org_id))
        return jsonify({'access_token': access_token, 'org_id': org_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ Findings ============
@app.route('/api/findings', methods=['GET'])
@jwt_required()
def get_findings():
    """Get findings for organization"""
    org_id = int(get_jwt_identity())
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute('''SELECT id, vector_type, severity, description, created_at 
                     FROM findings WHERE org_id = ? ORDER BY created_at DESC''', (org_id,))
        findings = []
        for row in c.fetchall():
            findings.append({
                'id': row[0],
                'vector_type': row[1],
                'severity': row[2],
                'description': row[3],
                'created_at': row[4]
            })
        
        conn.close()
        return jsonify({'findings': findings}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['POST'])
@jwt_required()
def post_findings():
    """Submit findings"""
    org_id = int(get_jwt_identity())
    
    try:
        data = request.get_json()
        vector_type = data.get('vector_type')
        severity = data.get('severity')
        description = data.get('description')
        remediation = data.get('remediation', '')
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        c.execute('''INSERT INTO findings (org_id, vector_type, severity, description, remediation)
                     VALUES (?, ?, ?, ?, ?)''',
                  (org_id, vector_type, severity, description, remediation))
        
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'ok', 'finding_id': c.lastrowid}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ Threat Intelligence ============
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

# ============ Compliance Reports ============
@app.route('/api/reports/compliance', methods=['GET'])
@jwt_required()
def compliance_report():
    """Get compliance report"""
    org_id = int(get_jwt_identity())
    
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        
        # Calculate compliance score
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "CRITICAL"', (org_id,))
        critical = c.fetchone()[0]
        
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "HIGH"', (org_id,))
        high = c.fetchone()[0]
        
        score = max(0, 100 - (critical*40 + high*20))
        
        conn.close()
        
        return jsonify({
            'compliance_score': score,
            'critical_findings': critical,
            'high_findings': high,
            'report_date': datetime.now().isoformat()
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=7777, debug=False)
