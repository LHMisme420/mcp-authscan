from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
CORS(app, origins="*")  # Allow all origins

app.config['JWT_SECRET_KEY'] = 'dev-secret-key-change-in-production'
jwt = JWTManager(app)

DB_FILE = 'vata.db'

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS organizations
        (id INTEGER PRIMARY KEY, name TEXT, api_key TEXT, created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS findings
        (id INTEGER PRIMARY KEY, org_id INTEGER, server_url TEXT, vector_type TEXT, severity TEXT, created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS compliance_reports
        (id INTEGER PRIMARY KEY, org_id INTEGER, framework TEXT, score INTEGER, breakdown TEXT, created_at TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS api_audit_log
        (id INTEGER PRIMARY KEY, org_id INTEGER, endpoint TEXT, method TEXT, status INTEGER, created_at TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200

@app.route('/auth/register', methods=['POST'])
def register():
    try:
        org_name = request.json.get('org_name', 'DefaultOrg')
        api_key = f'vata_key_{os.urandom(16).hex()}'
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO organizations (name, api_key, created_at) VALUES (?, ?, ?)',
                  (org_name, api_key, datetime.utcnow().isoformat()))
        conn.commit()
        org_id = c.lastrowid
        conn.close()
        
        return jsonify({'org_id': org_id, 'api_key': api_key}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    try:
        api_key = request.json.get('api_key')
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT id FROM organizations WHERE api_key = ?', (api_key,))
        org = c.fetchone()
        conn.close()
        
        if not org:
            return jsonify({'error': 'Invalid API key'}), 401
        
        access_token = create_access_token(identity=str(org[0]))
        return jsonify({'access_token': access_token}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/findings', methods=['GET'])
@jwt_required()
def get_findings():
    try:
        org_id = int(get_jwt_identity())
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT server_url, vector_type, severity FROM findings WHERE org_id = ?', (org_id,))
        findings = [{'server_url': row[0], 'vector_type': row[1], 'severity': row[2]} for row in c.fetchall()]
        conn.close()
        return jsonify({'findings': findings}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/reports/compliance', methods=['POST'])
@jwt_required()
def compliance_report():
    try:
        org_id = int(get_jwt_identity())
        framework = request.json.get('framework', 'SOC2')
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT severity FROM findings WHERE org_id = ?', (org_id,))
        severities = [row[0] for row in c.fetchall()]
        conn.close()
        
        breakdown = {
            'CRITICAL': severities.count('CRITICAL'),
            'HIGH': severities.count('HIGH'),
            'MEDIUM': severities.count('MEDIUM'),
            'LOW': severities.count('LOW')
        }
        
        compliance_score = 100
        if breakdown['CRITICAL'] > 0:
            compliance_score -= 40
        if breakdown['HIGH'] > 0:
            compliance_score -= 20
        if breakdown['MEDIUM'] > 0:
            compliance_score -= 10
        
        compliance_score = max(0, compliance_score)
        
        return jsonify({
            'framework': framework,
            'compliance_score': compliance_score,
            'severity_breakdown': breakdown
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
