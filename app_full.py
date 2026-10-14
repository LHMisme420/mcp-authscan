from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import sqlite3
import json
import os
from datetime import datetime, timedelta
import subprocess
import threading

app = Flask(__name__)
CORS(app)

# Config
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET', 'dev-secret-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

PORT = int(os.environ.get('PORT', 5000))
DB_FILE = os.environ.get('DB_FILE', '/tmp/vata.db')

# ============ DATABASE ============
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Organizations table
    c.execute('''CREATE TABLE IF NOT EXISTS organizations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        api_key TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Findings table
    c.execute('''CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        server_name TEXT,
        rule TEXT,
        severity TEXT,
        description TEXT,
        remediation TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(org_id) REFERENCES organizations(id)
    )''')
    
    # Scans table (track scan history)
    c.execute('''CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        org_id INTEGER NOT NULL,
        scan_type TEXT,
        target TEXT,
        status TEXT,
        findings_count INTEGER,
        started_at TIMESTAMP,
        completed_at TIMESTAMP,
        FOREIGN KEY(org_id) REFERENCES organizations(id)
    )''')
    
    conn.commit()
    conn.close()

init_db()

# ============ AUTH ENDPOINTS ============
@app.route('/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        org_name = data.get('org_name', f'org_{int(__import__("time").time())}')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM organizations WHERE name = ?', (org_name,))
        existing = c.fetchone()
        if existing:
            org_id = existing[0]
        else:
            c.execute('INSERT INTO organizations (name, api_key) VALUES (?, ?)', (org_name, f'key_{org_name}'))
            conn.commit()
            org_id = c.lastrowid
        access_token = create_access_token(identity=str(org_id))
        conn.close()
        return jsonify({'access_token': access_token, 'org_id': org_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        org_name = data.get('org_name')
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM organizations WHERE name = ?', (org_name,))
        result = c.fetchone()
        conn.close()
        if not result:
            return jsonify({'error': 'Not found'}), 404
        org_id = result[0]
        access_token = create_access_token(identity=str(org_id))
        return jsonify({'access_token': access_token, 'org_id': org_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ FINDINGS API ============
@app.route('/api/findings', methods=['GET'])
@jwt_required()
def get_findings():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id, server_name, rule, severity, description, created_at FROM findings WHERE org_id = ? ORDER BY created_at DESC', (org_id,))
        findings = [{'id': r[0], 'server': r[1], 'rule': r[2], 'severity': r[3], 'description': r[4], 'created_at': r[5]} for r in c.fetchall()]
        conn.close()
        return jsonify({'findings': findings}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['POST'])
@jwt_required()
def post_findings():
    org_id = get_jwt_identity()
    try:
        data = request.get_json()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO findings (org_id, server_name, rule, severity, description, remediation) VALUES (?, ?, ?, ?, ?, ?)',
                 (org_id, data.get('server_name'), data.get('rule'), data.get('severity'), data.get('description'), data.get('remediation', '')))
        conn.commit()
        conn.close()
        return jsonify({'status': 'ok'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ THREAT INTELLIGENCE ============
@app.route('/api/threat-intelligence', methods=['GET'])
@jwt_required()
def threat_intelligence():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT severity FROM findings WHERE org_id = ? ORDER BY created_at DESC LIMIT 100', (org_id,))
        recent = [r[0] for r in c.fetchall()]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND created_at > datetime("now", "-7 days")', (org_id,))
        week = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND created_at > datetime("now", "-30 days")', (org_id,))
        month = c.fetchone()[0]
        conn.close()
        return jsonify({
            'total_findings': len(recent), 
            'critical': recent.count('CRITICAL'), 
            'high': recent.count('HIGH'), 
            'medium': recent.count('MEDIUM'),
            'low': recent.count('LOW'),
            'week_trend': week, 
            'month_trend': month, 
            'trend_direction': 'increasing' if week > month/4 else 'decreasing'
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ COMPLIANCE SCORING ============
@app.route('/api/reports/compliance', methods=['GET'])
@jwt_required()
def compliance_report():
    org_id = get_jwt_identity()
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "CRITICAL"', (org_id,))
        critical = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ? AND severity = "HIGH"', (org_id,))
        high = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM findings WHERE org_id = ?', (org_id,))
        total = c.fetchone()[0]
        conn.close()
        if total == 0:
            score = 100
        else:
            risk_points = (critical * 100) + (high * 50)
            score = max(0, min(100, 100 - (risk_points / total)))
        return jsonify({'compliance_score': int(score), 'critical_findings': critical, 'high_findings': high, 'total_findings': total}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============ SCANNING ORCHESTRATION ============
@app.route('/api/scans/mcp', methods=['POST'])
@jwt_required()
def scan_mcp_servers():
    org_id = get_jwt_identity()
    try:
        data = request.get_json()
        servers = data.get('servers', [])
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO scans (org_id, scan_type, target, status, started_at) VALUES (?, ?, ?, ?, datetime("now"))',
                 (org_id, 'mcp', ','.join(servers), 'running'))
        scan_id = c.lastrowid
        conn.commit()
        conn.close()
        
        # Run scan async
        threading.Thread(target=run_mcp_scan, args=(org_id, scan_id, servers)).start()
        
        return jsonify({'scan_id': scan_id, 'status': 'running'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def run_mcp_scan(org_id, scan_id, servers):
    """Run mcp-authscan on servers and import findings"""
    try:
        for server in servers:
            # Run mcp_authscan.py
            result = subprocess.run(
                ['python3', 'mcp_authscan.py', f'http://{server}', '--json'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                findings_json = json.loads(result.stdout)
                conn = sqlite3.connect(DB_FILE)
                c = conn.cursor()
                for finding in findings_json.get('findings', []):
                    c.execute('INSERT INTO findings (org_id, server_name, rule, severity, description) VALUES (?, ?, ?, ?, ?)',
                             (org_id, server, finding.get('rule'), finding.get('severity'), finding.get('evidence', '')))
                conn.commit()
                conn.close()
    except Exception as e:
        print(f"Scan error: {e}")
    finally:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('UPDATE scans SET status = ?, completed_at = datetime("now") WHERE id = ?', ('completed', scan_id))
        conn.commit()
        conn.close()

# ============ HEALTH CHECK ============
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=False)
